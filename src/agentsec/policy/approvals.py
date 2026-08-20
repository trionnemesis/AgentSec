"""Approval tokens for high-risk runs.

Approvals are scoped (scenario + target), time-bounded, and single-use. The
gateway never mints one: an approval must be created out-of-band by a human, so
that a compromised or over-eager model cannot approve its own request.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from getpass import getuser
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentsec.errors import ConfigError


class Approval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str
    scenario_id: str
    target_id: str
    approved_by: str
    expires_at: datetime
    reason: str = ""
    consumed_at: datetime | None = None
    consumed_by_run: str | None = None

    def is_valid_for(
        self, scenario_id: str, target_id: str, *, now: datetime | None = None
    ) -> bool:
        now = now or datetime.now(UTC)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        return (
            self.consumed_at is None
            and expires > now
            and self.scenario_id in (scenario_id, "*")
            and self.target_id in (target_id, "*")
        )

    def invalid_reason(
        self, scenario_id: str, target_id: str, *, now: datetime | None = None
    ) -> str:
        now = now or datetime.now(UTC)
        expires = (
            self.expires_at if self.expires_at.tzinfo
            else self.expires_at.replace(tzinfo=UTC)
        )
        if self.consumed_at is not None:
            return f"approval already consumed by run {self.consumed_by_run}"
        if expires <= now:
            return f"approval expired at {expires.isoformat()}"
        if self.scenario_id not in (scenario_id, "*"):
            return f"approval is scoped to scenario {self.scenario_id}"
        if self.target_id not in (target_id, "*"):
            return f"approval is scoped to target {self.target_id}"
        return "approval is valid"


class ApprovalFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    apiVersion: str = "agentsec.dev/v1"
    kind: str = "ApprovalLedger"
    approvals: list[Approval] = Field(default_factory=list)


class ApprovalStore:
    """File-backed approval ledger.

    A YAML file is the right primitive for the local-first MVP: it is
    reviewable, diffable and can be committed. A team deployment should swap
    this for the company's change-management system behind the same interface.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    @property
    def _lock_path(self) -> Path:
        # Keep the coordination inode out of the operator's policy directory:
        # normal approval use must not create an untracked repository file.
        if os.name == "nt":
            user_namespace = hashlib.sha256(
                os.path.normcase(getuser()).encode("utf-8")
            ).hexdigest()[:32]
        else:
            user_namespace = str(os.geteuid())
        lock_key_path = str(self.path.resolve())
        if os.name == "nt":
            lock_key_path = os.path.normcase(lock_key_path)
        key = hashlib.sha256(lock_key_path.encode("utf-8")).hexdigest()
        root = Path(tempfile.gettempdir()) / f"agentsec-approval-locks-{user_namespace}"
        return root / f"{key}.lock"

    @staticmethod
    def _unsafe_lock(message: str) -> ConfigError:
        return ConfigError(message)

    def _ensure_lock_root(self) -> Path:
        root = self._lock_path.parent
        try:
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
        except FileExistsError:
            # ``mkdir(exist_ok=True)`` may report a pre-existing symlink as a
            # collision on some platforms.  Let lstat below classify it
            # without following it.
            pass
        except OSError as exc:
            raise self._unsafe_lock("approval lock root is unavailable") from exc
        try:
            info = os.lstat(root)
        except OSError as exc:
            raise self._unsafe_lock("approval lock root is unavailable") from exc

        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise self._unsafe_lock("approval lock root is unsafe")
        if os.name != "nt" and (
            info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise self._unsafe_lock("approval lock root has unsafe ownership or permissions")
        return root

    def _open_posix_lock(self, root: Path) -> tuple[int, int]:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory = getattr(os, "O_DIRECTORY", 0)
        try:
            root_fd = os.open(root, os.O_RDONLY | directory | nofollow)
        except OSError as exc:
            raise self._unsafe_lock("approval lock root is unsafe") from exc

        try:
            root_info = os.fstat(root_fd)
            if (
                not stat.S_ISDIR(root_info.st_mode)
                or root_info.st_uid != os.geteuid()
                or stat.S_IMODE(root_info.st_mode) & 0o077
            ):
                raise self._unsafe_lock("approval lock root has unsafe ownership or permissions")
            try:
                lock_fd = os.open(
                    self._lock_path.name,
                    os.O_RDWR | os.O_CREAT | nofollow,
                    0o600,
                    dir_fd=root_fd,
                )
            except OSError as exc:
                raise self._unsafe_lock("approval lock file is unsafe") from exc
        except Exception:
            os.close(root_fd)
            raise

        try:
            lock_info = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(lock_info.st_mode)
                or lock_info.st_uid != os.geteuid()
                or stat.S_IMODE(lock_info.st_mode) != 0o600
            ):
                raise self._unsafe_lock("approval lock file has unsafe ownership or permissions")
        except Exception:
            os.close(lock_fd)
            os.close(root_fd)
            raise
        return root_fd, lock_fd

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Serialize ledger read/modify/write operations across processes."""
        root = self._ensure_lock_root()
        if os.name == "nt":
            lock_path = self._lock_path
            if lock_path.is_symlink():
                raise self._unsafe_lock("approval lock file is unsafe")
            with lock_path.open("a+b") as lock_file:
                # ``msvcrt.locking`` requires a byte to exist at the locked
                # offset.  The lock file is coordination-only and contains no
                # policy data.
                import msvcrt

                lock_file.seek(0, os.SEEK_END)
                if lock_file.tell() == 0:
                    lock_file.write(b"0")
                    lock_file.flush()
                lock_file.seek(0)
                msvcrt.locking(  # type: ignore[attr-defined]
                    lock_file.fileno(), msvcrt.LK_LOCK, 1  # type: ignore[attr-defined]
                )
                try:
                    yield
                finally:
                    lock_file.seek(0)
                    msvcrt.locking(  # type: ignore[attr-defined]
                        lock_file.fileno(), msvcrt.LK_UNLCK, 1  # type: ignore[attr-defined]
                    )
            return

        import fcntl

        root_fd, lock_fd = self._open_posix_lock(root)
        try:
            lock_file = os.fdopen(lock_fd, "a+b", closefd=True)
        except Exception:
            os.close(root_fd)
            raise
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        finally:
            lock_file.close()
            os.close(root_fd)

    def _read_unlocked(self) -> ApprovalFile:
        if not self.path.is_file():
            return ApprovalFile()
        try:
            data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(_yaml_error_message(self.path.name, exc)) from exc
        try:
            return ApprovalFile.model_validate(data)
        except ValidationError as exc:
            detail = "; ".join(
                f"{'/'.join(str(part) for part in error['loc']) or '(root)'}: "
                f"{error['msg']}"
                for error in exc.errors(include_input=False, include_url=False)
            )
            raise ConfigError(
                f"{self.path.name}: invalid approval configuration: {detail}"
            ) from exc
        except Exception as exc:
            raise ConfigError(
                f"{self.path.name}: invalid approval configuration ({type(exc).__name__})"
            ) from exc

    def _read(self) -> ApprovalFile:
        with self._locked():
            return self._read_unlocked()

    def _write_unlocked(self, ledger: ApprovalFile) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temp_file:
                temp_path = Path(temp_file.name)
                temp_file.write(
                    yaml.safe_dump(
                        ledger.model_dump(mode="json"),
                        sort_keys=False,
                        allow_unicode=True,
                    )
                )
                temp_file.flush()
                os.fsync(temp_file.fileno())
            os.replace(temp_path, self.path)
            temp_path = None
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def list(self) -> list[Approval]:
        return self._read().approvals

    def get(self, approval_id: str) -> Approval | None:
        for a in self._read().approvals:
            if a.approval_id == approval_id:
                return a
        return None

    def grant(
        self,
        *,
        scenario_id: str,
        target_id: str,
        approved_by: str,
        ttl_minutes: int = 60,
        reason: str = "",
    ) -> Approval:
        approval = Approval(
            approval_id="apr_" + secrets.token_hex(8),
            scenario_id=scenario_id,
            target_id=target_id,
            approved_by=approved_by,
            expires_at=datetime.now(UTC) + timedelta(minutes=ttl_minutes),
            reason=reason,
        )
        with self._locked():
            ledger = self._read_unlocked()
            ledger.approvals.append(approval)
            self._write_unlocked(ledger)
        return approval

    def consume(self, approval_id: str, run_id: str) -> bool:
        """Atomically claim an unused approval for one run.

        The lock covers the ledger read and conditional write, so callers that
        both observed a valid token cannot both claim it.  ``False`` is an
        explicit compare-and-set failure; it is never a silent success.
        """
        with self._locked():
            ledger = self._read_unlocked()
            for approval in ledger.approvals:
                if approval.approval_id == approval_id and approval.consumed_at is None:
                    approval.consumed_at = datetime.now(UTC)
                    approval.consumed_by_run = run_id
                    self._write_unlocked(ledger)
                    return True
        return False


def _yaml_error_message(filename: str, error: yaml.YAMLError) -> str:
    mark = getattr(error, "problem_mark", None)
    if mark is None:
        return f"{filename}: invalid YAML ({type(error).__name__})"
    return (
        f"{filename}: invalid YAML ({type(error).__name__}) at "
        f"line {mark.line + 1}, column {mark.column + 1}"
    )

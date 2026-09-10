# 外部 CI 安裝 / External CI installation

This is the first implementation slice of #50: immutable AgentSec installation,
the bundled catalogue, frozen source identity and synchronous gate output.
Project scenario overlays and the asynchronous lifecycle remain follow-ups.

本階段處理 #50 的固定版本安裝、內建情境目錄、來源快照與同步閘門。
專案情境疊加／覆寫及非同步生命週期留在後續工作；本 PR 不關閉整張 #50。

## 原則 / Principles

- The consumer owns targets, policy and evidence. AgentSec's reviewed commit
  owns its code and built-in catalogue. Installing the consumer is never a
  substitute for installing AgentSec.
- 消費端管理 target、policy 與 evidence；AgentSec 的固定 commit 管理程式與內建
  catalogue。兩份 checkout 使用獨立目錄。
- Source identity is captured on each run, including refusal and dry run.
  Regenerating a report does not substitute the currently installed version.
- 每次執行保存來源快照；重產報表沿用歷史快照。舊資料缺欄位時顯示未知。
- Package provenance does not change `recorded/live/mixed`, the four axes,
  verdict precedence, target-driver semantics, or evidence correlation.
- 套件來源不影響證據來源分類、四軸、判定優先序、target driver 或 evidence correlation。

## Caller 設定 / Caller setup

The consumer needs an operator-reviewed `policy/targets.yaml`; profiles are
optional and otherwise use the existing defaults. Fixture targets also need
their recorded evidence files. Neither AgentSec source nor built-in scenarios
are copied into the consumer repository. The selected workspace must have a
fresh, empty (or absent) `results/` directory to prevent stale output reuse.

消費端準備經維運者審核的 target allowlist；fixture target 另需對應的記錄檔。
`results/` 必須為空或尚未存在。無須將 AgentSec 程式或內建 scenarios 放進消費端。

Replace both placeholders below with reviewed, full lowercase commit SHAs.
The workflow SHA must contain this implementation; the installation SHA must
contain the bundled-catalogue support. They are separately selected identities.
This example intentionally has no default release or moving-branch fallback.

請將以下兩個佔位符換成已審核的完整 SHA；這是設定範本，不是已執行的驗證紀錄。

```yaml
name: AgentSec 安全閘門 / Purple gate
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  purple:
    uses: trionnemesis/AgentSec/.github/workflows/agentsec-gate.yml@<REVIEWED_WORKFLOW_SHA>
    with:
      agentsec-sha: <REVIEWED_AGENTSEC_SHA>
      target: <YOUR_ALLOWLISTED_TARGET>
      profile: pr
      workspace: .
      fail-on-blocking: true
```

The workflow checks out the consumer at `consumer/` and AgentSec at
`agentsec-tool/`. It checks the latter's actual HEAD, installs its committed
content non-editably through a local Git URL into an isolated virtualenv, and
checks the installer's PEP 610 `vcs_info.commit_id` against the requested SHA.
Metadata must describe the module actually imported; a source checkout
shadowing the installed package fails validation. The local Git URL is never
published because it contains runner paths.

流程先核對 checkout HEAD，再透過本機 Git URL 安裝固定 commit，最後核對實際
安裝器 metadata 與載入模組位置。Caller 傳入的 SHA 本身不構成安裝證據。
Caller 的 `github.workflow_ref`／`github.workflow_sha` 僅標示 caller workflow，
不得誤稱為被呼叫 workflow 的身分；後者由 caller YAML 的固定 `uses:` 宣告。

## 目錄與來源 / Catalogue and source identity

The workflow sets `AGENTSEC_CATALOGUE=builtin` and
`AGENTSEC_EXPECTED_SHA=<commit>`. Builtin mode reads only installed package data;
there is no source-checkout fallback. A nonempty consumer `scenarios/` is an
explicit unsupported-overlay error, even if its IDs do not collide. Ordinary
workspace mode remains the default for existing development workspaces.

Built-in 模式僅載入安裝套件內的 catalogue；不支援的專案 scenarios 明確拒絕。
既有開發工作目錄仍預設使用 workspace 模式。

Every run's nullable `source_provenance` contains:

| Field | 意義 / Meaning |
|---|---|
| `package_version` | 安裝套件版本 / Installed distribution version; unknown if absent |
| `package_commit` | 安裝器記錄的完整 Git SHA / Resolved installed VCS commit; unknown for non-VCS/editable installs |
| `catalogue_origin` | `builtin` or `workspace` |
| `catalogue_ref` | Builtin catalogue 的版本 SHA / Installed commit for built-ins; null for workspace catalogues |
| `catalogue_digest` | 排序後的契約摘要與引用 payload 內容摘要 / SHA-256 over sorted effective contracts and referenced UTF-8 payload contents |
| `scenario_digest` | 既有正規化契約 SHA-256 / Existing canonical contract digest, matching `Run.scenario_digest` |

Scenario ID remains the run's existing `scenario_id`. There is no invented
scenario semver: immutable refs and content digests identify the version.
Source snapshots are stored in the existing Run JSON payload without a new
database table. Published report schema 1.5.0 adds the nullable field; JSON,
HTML and every JUnit testcase carry it, including secure cases. Legacy rows
stay null/unknown and are never backfilled from current files.

欄位新增於報表 schema 1.5.0；舊紀錄維持未知，不回填現在的版本。
此處固定的是 AgentSec 身分；相依套件仍使用既有版本範圍，不宣稱整個 Python
環境可逐位元重現，也不提供密碼學簽章保證。

## 失敗處理 / Failure handling

`fail-on-blocking: false` permits completed security-gap findings to be reported
without blocking. Missing/mismatched installation identity, missing catalogue,
overlays, configuration failures, empty reports, incomplete runs and `error`
verdicts still fail the job. An Actions cancellation is not an AgentSec terminal
`cancelled` state and does not prove target cleanup; lifecycle guarantees belong
to the separate follow-up. Actions concurrency is not a cross-entrypoint quota.

僅回報模式仍會拒絕安裝、設定、來源與無法評估等錯誤。取消、租約、恢復、
跨 CLI／MCP／CI 的中央限流不在本階段；亦不更動 #48 或 #49。

## 驗證邊界 / Verification boundary

`tests/test_consumer_install.py` creates two independent Git repositories,
installs an actual producer commit, deletes that producer checkout, then runs
the installed CLI against the consumer's unchanged recorded fixture corpus.
It checks all four original scenarios, the known two blocking results,
JUnit/HTML/JSON source identity and refusal of a mismatched installation SHA.
The consumer contains no AgentSec source, packaging metadata or scenarios.

這個測試驗證跨 Git repo 的安裝與執行邊界；不等於另一個 GitHub repository
已成功觸發遠端 `workflow_call`。正式外部採用前，維護者應以本範本在選定的
consumer repo 執行一次並將 Actions URL 與 artifacts 附回 #50。
未取得該紀錄前，不宣稱 hosted cross-repository acceptance 已完成。

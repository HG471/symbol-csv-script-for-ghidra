# symbol-csv-script-for-ghidra

Ghidra scripts to export / import symbol names as CSV.

Ghidra でシンボル名を CSV に書き出し / 読み込みするスクリプトです。

`FUN_...` や `switchD_...` などの自動生成名は除外されます。

アドレスは `BASE` からのオフセットで保存されます（初期値 `0x7100000000`。別のベースで使うときはスクリプト先頭の `BASE` を変更）。

## Modes / 切り替え

スクリプト先頭の定数で切り替えます。

**Export**

| `MANGLED` | 動作 |
|---|---|
| `"split"` | `_Z` で始まるマングル名を `<name>_mangled.<ext>` に分けて出力 (デフォルト) |
| `"skip"` | マングル名を出力しない |
| `"keep"` | 1 ファイルにまとめる |

**Import**

| 定数 | 動作 |
|---|---|
| `RENAME_EXISTING_FUNCTIONS` | 既存の関数名を CSV の名前で上書き (デフォルトはTrue) |
| `CREATE_MISSING_FUNCTIONS` | 関数が無いアドレスに関数を作成（デフォルトはFalse） |

`test_data_*` was generated using the following Powershell function, using `64kb` as the size for the first four,
then the remaining four used `37kb`, `185kb`, `1mb`, and `2mb+18kb`:

```ps
$chars = [char[]] ([char]'0'..[char]'9' + [char]'A'..[char]'Z' + [char]'a'..[char]'z')
$chars = $chars * 126

function Random-File([string]$filename, [int]$size) {
  (1..($size/128)).foreach({-join (Get-Random $chars -Count 126) | add-content $filename })
}
```

`test_data_*.b3` is the binary hash result of BLAKE3 on the corresponding `test_data_*` file.
It uses the reference Rust implementation, and they are generated using the following Powershell
script:

```ps
function Pipe-HexToBytes {
  process {
    $bytes = [byte[]]::new($_.Length / 2)
    for ($i = 0; $i -lt $_.Length; $i += 2) {
      $bytes[$i/2] = [Convert]::ToByte($_.Substring($i, 2), 16)
    }
    $bytes
  }
}

gci test_data_* | % { b3sum --no-names $_ | pipe-hextobytes | set-content ($_.FullName + ".b3") -encoding byte }
```
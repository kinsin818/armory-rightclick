param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$OutFile,
    [string]$Lang = 'zh-Hans-CN'
)

# 用 Windows 自带 OCR 引擎（Windows.Media.Ocr）识别文字。
# 本地执行，不联网，不消耗任何额度。需要系统装了对应语言的 OCR 包。
# 结果写 UTF-8 文件，避免 PowerShell 控制台编码污染中文。

$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Runtime.WindowsRuntime

$null = [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
$null = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
$null = [Windows.Media.Ocr.OcrEngine, Windows.Media.Ocr, ContentType = WindowsRuntime]

$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and
        $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    })[0]

function Await($Op, $ResultType) {
    $m = $asTaskGeneric.MakeGenericMethod($ResultType)
    $t = $m.Invoke($null, @($Op))
    $t.Wait(-1) | Out-Null
    return $t.Result
}

try {
    $file = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($Path)) ([Windows.Storage.StorageFile])
    $stream = Await ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
    $decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
    $bitmap = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])

    $engine = $null
    if ($Lang) {
        try {
            $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage([Windows.Globalization.Language]::new($Lang))
        } catch { $engine = $null }
    }
    if (-not $engine) {
        $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
    }
    if (-not $engine) {
        [IO.File]::WriteAllText($OutFile, '__OCR_NO_ENGINE__', [Text.Encoding]::UTF8)
        exit 2
    }

    $result = Await ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
    [IO.File]::WriteAllText($OutFile, $result.Text, [Text.Encoding]::UTF8)
    exit 0
}
catch {
    [IO.File]::WriteAllText($OutFile, "__OCR_ERROR__: $($_.Exception.Message)", [Text.Encoding]::UTF8)
    exit 3
}

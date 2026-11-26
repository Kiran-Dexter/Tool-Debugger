<#
.SYNOPSIS
    Exports Active Directory users with their group memberships, and groups with their
    members, into a fully formatted Excel workbook (.xlsx).

.DESCRIPTION
    Designed for Windows Server 2019 (PowerShell 5.1) with the ActiveDirectory module
    (installed on every Domain Controller, or via RSAT on a member server).

    Excel does NOT need to be installed and no extra modules are required - the .xlsx
    file is generated directly (Open XML), so it is safe to run on a Domain Controller.

    Workbook sheets:
      1. Summary             - counts per domain
      2. Users               - one row per user: domain, username, display name,
                               description, account status, dates, OU and a list of groups
      3. User Groups         - one row per user/group pair (easy to filter by user or group)
      4. Groups & Members    - one row per group member, grouped by group, including
                               empty groups

    Formatting: titled sheets, styled header row, frozen panes, auto-filter, banded rows,
    borders, sized columns, real Excel date values, disabled accounts highlighted in red,
    landscape / fit-to-width printing with repeating header rows.

    Primary-group membership (e.g. "Domain Users"), which AD does not store in the
    member/memberOf attributes, is added for user accounts and marked "Primary Group".

.PARAMETER OutputPath
    Full path of the .xlsx file to create. Default: Desktop\AD_Users_Groups_<date>.xlsx

.PARAMETER Domain
    One or more domain DNS names to export. Default: the current domain.

.PARAMETER AllForestDomains
    Export every domain in the current forest.

.EXAMPLE
    .\Export-ADUsersGroups.ps1

.EXAMPLE
    .\Export-ADUsersGroups.ps1 -OutputPath C:\Reports\AD_Report.xlsx

.EXAMPLE
    .\Export-ADUsersGroups.ps1 -AllForestDomains

.EXAMPLE
    .\Export-ADUsersGroups.ps1 -Domain contoso.com, emea.contoso.com
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath,
    [string[]]$Domain,
    [switch]$AllForestDomains
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression

#region ======================== XLSX WRITER (no Excel needed) ========================

$script:Inv = [System.Globalization.CultureInfo]::InvariantCulture

function ConvertTo-XmlSafe {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    # Remove characters that are illegal in XML, enforce Excel's 32,767-char cell limit
    $clean = $Text -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
    if ($clean.Length -gt 32000) { $clean = $clean.Substring(0, 32000) + ' ...[truncated]' }
    return [System.Security.SecurityElement]::Escape($clean)
}

function Get-ColumnLetter {
    param([int]$Index)   # 1-based
    $s = ''
    while ($Index -gt 0) {
        $m = ($Index - 1) % 26
        $s = ([char](65 + $m)).ToString() + $s
        $Index = [int](($Index - 1 - $m) / 26)
    }
    return $s
}

function Get-SheetLayout {
    param([hashtable]$Sheet)
    $rowCount = if ($Sheet.Rows) { $Sheet.Rows.Count } else { 0 }
    $hdr      = if ($Sheet.Title) { 4 } else { 1 }
    $maxData  = 1048576 - $hdr
    if ($rowCount -gt $maxData) { $rowCount = $maxData }
    [pscustomobject]@{
        HeaderRow  = $hdr
        FirstRow   = $hdr + 1
        LastRow    = $hdr + [math]::Max($rowCount, 1)
        RowCount   = $rowCount
        LastLetter = Get-ColumnLetter @($Sheet.Columns).Count
    }
}

function Write-XlsxSheet {
    param(
        [System.IO.StreamWriter]$Writer,
        [hashtable]$Sheet,
        [bool]$Selected
    )
    $cols    = @($Sheet.Columns)
    $rows    = $Sheet.Rows
    $layout  = Get-SheetLayout $Sheet
    $hdr     = $layout.HeaderRow
    $first   = $layout.FirstRow
    $last    = $layout.LastRow
    $letters = @(for ($i = 1; $i -le $cols.Count; $i++) { Get-ColumnLetter $i })
    $lastL   = $layout.LastLetter

    if ($rows -and $rows.Count -gt $layout.RowCount) {
        Write-Warning "Sheet '$($Sheet.Name)' has $($rows.Count) rows - truncated to Excel's limit of $($layout.RowCount)."
    }

    # ---- Column widths (sampled from data) ----
    $widths = New-Object 'System.Collections.Generic.List[double]'
    $sample = if ($rows) { [math]::Min($rows.Count, 5000) } else { 0 }
    foreach ($c in $cols) {
        $w = [math]::Max(10, $c.Header.Length + 5)
        if ($c.Width)                { $w = $c.Width }
        elseif ($c.Type -eq 'Date')  { $w = [math]::Max($w, 17) }
        else {
            $max = 0
            for ($j = 0; $j -lt $sample; $j++) {
                $v = $rows[$j][$c.Key]
                if ($null -ne $v) { $len = ([string]$v).Length; if ($len -gt $max) { $max = $len } }
            }
            $cap = if ($c.MaxWidth) { $c.MaxWidth } else { 60 }
            $w = [math]::Max($w, [math]::Min($max + 2, $cap))
        }
        $widths.Add([double]$w)
    }

    # ---- Sheet header ----
    $Writer.Write('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    $Writer.Write('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">')
    $tab = if ($Sheet.TabColor) { "<tabColor rgb=`"$($Sheet.TabColor)`"/>" } else { '' }
    $Writer.Write("<sheetPr>$tab<pageSetUpPr fitToPage=`"1`"/></sheetPr>")
    $Writer.Write("<dimension ref=`"A1:$lastL$last`"/>")

    $sel = if ($Selected) { ' tabSelected="1"' } else { '' }
    $fc  = [int]$Sheet.FreezeColumns
    if ($fc -gt 0 -and $fc -lt $cols.Count) {
        $tl = "$($letters[$fc])$first"
        $Writer.Write("<sheetViews><sheetView workbookViewId=`"0`"$sel><pane xSplit=`"$fc`" ySplit=`"$hdr`" topLeftCell=`"$tl`" activePane=`"bottomRight`" state=`"frozen`"/><selection pane=`"bottomRight`" activeCell=`"$tl`" sqref=`"$tl`"/></sheetView></sheetViews>")
    } else {
        $Writer.Write("<sheetViews><sheetView workbookViewId=`"0`"$sel><pane ySplit=`"$hdr`" topLeftCell=`"A$first`" activePane=`"bottomLeft`" state=`"frozen`"/><selection pane=`"bottomLeft`" activeCell=`"A$first`" sqref=`"A$first`"/></sheetView></sheetViews>")
    }
    $Writer.Write('<sheetFormatPr defaultRowHeight="15"/><cols>')
    for ($i = 0; $i -lt $cols.Count; $i++) {
        $Writer.Write("<col min=`"$($i+1)`" max=`"$($i+1)`" width=`"$($widths[$i].ToString($script:Inv))`" customWidth=`"1`"/>")
    }
    $Writer.Write('</cols><sheetData>')

    # ---- Title / subtitle ----
    if ($Sheet.Title) {
        $Writer.Write('<row r="1" ht="28" customHeight="1"><c r="A1" s="6" t="inlineStr"><is><t xml:space="preserve">' + (ConvertTo-XmlSafe $Sheet.Title) + '</t></is></c></row>')
        if ($Sheet.Subtitle) {
            $Writer.Write('<row r="2"><c r="A2" s="7" t="inlineStr"><is><t xml:space="preserve">' + (ConvertTo-XmlSafe $Sheet.Subtitle) + '</t></is></c></row>')
        }
    }

    # ---- Header row ----
    $Writer.Write("<row r=`"$hdr`" ht=`"30`" customHeight=`"1`">")
    for ($i = 0; $i -lt $cols.Count; $i++) {
        $Writer.Write("<c r=`"$($letters[$i])$hdr`" s=`"1`" t=`"inlineStr`"><is><t xml:space=`"preserve`">" + (ConvertTo-XmlSafe $cols[$i].Header) + '</t></is></c>')
    }
    $Writer.Write('</row>')

    # ---- Data rows ----
    # Styles: 2/3 text normal/banded, 4/5 date normal/banded, 8/9 highlighted text/date
    if ($layout.RowCount -eq 0) {
        $Writer.Write("<row r=`"$first`"><c r=`"A$first`" s=`"2`" t=`"inlineStr`"><is><t>(no data)</t></is></c></row>")
    } else {
        $band = $true; $prevKey = [guid]::NewGuid().ToString(); $r = $first
        $bandKey = $Sheet.BandKey; $warnKey = $Sheet.WarnKey
        for ($n = 0; $n -lt $layout.RowCount; $n++) {
            $row = $rows[$n]
            if ($bandKey) {
                $k = [string]$row[$bandKey]
                if ($k -ne $prevKey) { $band = -not $band; $prevKey = $k }
            } else { $band = -not $band }
            $warn  = $warnKey -and $row[$warnKey]
            $sText = if ($warn) { 8 } elseif ($band) { 3 } else { 2 }
            $sDate = if ($warn) { 9 } elseif ($band) { 5 } else { 4 }

            $Writer.Write("<row r=`"$r`">")
            for ($i = 0; $i -lt $cols.Count; $i++) {
                $c   = $cols[$i]
                $ref = "$($letters[$i])$r"
                $v   = $row[$c.Key]
                $isDate = $c.Type -eq 'Date'
                if ($null -eq $v -or ($v -is [string] -and $v.Length -eq 0)) {
                    $s = if ($isDate) { $sDate } else { $sText }
                    $Writer.Write("<c r=`"$ref`" s=`"$s`"/>")
                    continue
                }
                if ($isDate) {
                    $Writer.Write("<c r=`"$ref`" s=`"$sDate`"><v>" + ([datetime]$v).ToOADate().ToString($script:Inv) + '</v></c>')
                } elseif ($c.Type -eq 'Number') {
                    $Writer.Write("<c r=`"$ref`" s=`"$sText`"><v>" + ([double]$v).ToString($script:Inv) + '</v></c>')
                } else {
                    $Writer.Write("<c r=`"$ref`" s=`"$sText`" t=`"inlineStr`"><is><t xml:space=`"preserve`">" + (ConvertTo-XmlSafe ([string]$v)) + '</t></is></c>')
                }
            }
            $Writer.Write('</row>')
            $r++
        }
    }
    $Writer.Write('</sheetData>')
    $Writer.Write("<autoFilter ref=`"A$($hdr):$lastL$last`"/>")
    $Writer.Write('<pageMargins left="0.4" right="0.4" top="0.5" bottom="0.5" header="0.3" footer="0.3"/>')
    $Writer.Write('<pageSetup orientation="landscape" fitToWidth="1" fitToHeight="0"/>')
    $Writer.Write('</worksheet>')
}

function New-XlsxWorkbook {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object[]]$Sheets
    )
    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $dir  = Split-Path $Path -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (Test-Path $Path) { Remove-Item $Path -Force }

    $enc = New-Object System.Text.UTF8Encoding($false)
    $lvl = [System.IO.Compression.CompressionLevel]::Optimal
    $fs  = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew)
    $zip = New-Object System.IO.Compression.ZipArchive -ArgumentList $fs, ([System.IO.Compression.ZipArchiveMode]::Create), $false

    $addText = {
        param($Name, $Content)
        $entry = $zip.CreateEntry($Name, $lvl)
        $sw = New-Object System.IO.StreamWriter($entry.Open(), $enc)
        try { $sw.Write($Content) } finally { $sw.Dispose() }
    }

    try {
        $ns = 'http://schemas.openxmlformats.org'
        $ct = "<?xml version=`"1.0`" encoding=`"UTF-8`" standalone=`"yes`"?><Types xmlns=`"$ns/package/2006/content-types`">" +
              "<Default Extension=`"rels`" ContentType=`"application/vnd.openxmlformats-package.relationships+xml`"/>" +
              "<Default Extension=`"xml`" ContentType=`"application/xml`"/>" +
              "<Override PartName=`"/xl/workbook.xml`" ContentType=`"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml`"/>" +
              "<Override PartName=`"/xl/styles.xml`" ContentType=`"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml`"/>"
        for ($i = 1; $i -le $Sheets.Count; $i++) {
            $ct += "<Override PartName=`"/xl/worksheets/sheet$i.xml`" ContentType=`"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml`"/>"
        }
        $ct += '</Types>'
        & $addText '[Content_Types].xml' $ct

        & $addText '_rels/.rels' ("<?xml version=`"1.0`" encoding=`"UTF-8`" standalone=`"yes`"?><Relationships xmlns=`"$ns/package/2006/relationships`">" +
            "<Relationship Id=`"rId1`" Type=`"$ns/officeDocument/2006/relationships/officeDocument`" Target=`"xl/workbook.xml`"/></Relationships>")

        # Workbook + defined names (filter ranges and repeating print titles)
        $sheetXml = ''; $names = ''; $rels = ''
        for ($i = 0; $i -lt $Sheets.Count; $i++) {
            $s  = $Sheets[$i]
            $lo = Get-SheetLayout $s
            $sheetXml += "<sheet name=`"$(ConvertTo-XmlSafe $s.Name)`" sheetId=`"$($i+1)`" r:id=`"rId$($i+1)`"/>"
            $filter = "'{0}'!{1}A{1}{2}:{1}{3}{1}{4}" -f $s.Name, '$', $lo.HeaderRow, $lo.LastLetter, $lo.LastRow
            $titles = "'{0}'!{1}{2}:{1}{2}" -f $s.Name, '$', $lo.HeaderRow
            $names += "<definedName name=`"_xlnm._FilterDatabase`" localSheetId=`"$i`" hidden=`"1`">$(ConvertTo-XmlSafe $filter)</definedName>"
            $names += "<definedName name=`"_xlnm.Print_Titles`" localSheetId=`"$i`">$(ConvertTo-XmlSafe $titles)</definedName>"
            $rels  += "<Relationship Id=`"rId$($i+1)`" Type=`"$ns/officeDocument/2006/relationships/worksheet`" Target=`"worksheets/sheet$($i+1).xml`"/>"
        }
        $rels += "<Relationship Id=`"rId$($Sheets.Count+1)`" Type=`"$ns/officeDocument/2006/relationships/styles`" Target=`"styles.xml`"/>"

        & $addText 'xl/workbook.xml' ("<?xml version=`"1.0`" encoding=`"UTF-8`" standalone=`"yes`"?>" +
            "<workbook xmlns=`"$ns/spreadsheetml/2006/main`" xmlns:r=`"$ns/officeDocument/2006/relationships`">" +
            "<bookViews><workbookView activeTab=`"0`"/></bookViews><sheets>$sheetXml</sheets><definedNames>$names</definedNames></workbook>")

        & $addText 'xl/_rels/workbook.xml.rels' ("<?xml version=`"1.0`" encoding=`"UTF-8`" standalone=`"yes`"?><Relationships xmlns=`"$ns/package/2006/relationships`">$rels</Relationships>")

        # Styles
        $border = '<border><left style="thin"><color rgb="FFBFBFBF"/></left><right style="thin"><color rgb="FFBFBFBF"/></right><top style="thin"><color rgb="FFBFBFBF"/></top><bottom style="thin"><color rgb="FFBFBFBF"/></bottom><diagonal/></border>'
        $styles = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="$ns/spreadsheetml/2006/main">
<numFmts count="1"><numFmt numFmtId="164" formatCode="yyyy-mm-dd hh:mm"/></numFmts>
<fonts count="5">
<font><sz val="11"/><name val="Calibri"/><family val="2"/></font>
<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/><family val="2"/></font>
<font><b/><sz val="16"/><color rgb="FF1F4E78"/><name val="Calibri"/><family val="2"/></font>
<font><i/><sz val="10"/><color rgb="FF595959"/><name val="Calibri"/><family val="2"/></font>
<font><sz val="11"/><color rgb="FF9C0006"/><name val="Calibri"/><family val="2"/></font>
</fonts>
<fills count="5">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF1F4E78"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFDDEBF7"/><bgColor indexed="64"/></patternFill></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFFFC7CE"/><bgColor indexed="64"/></patternFill></fill>
</fills>
<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border>$border</borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="10">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top"/></xf>
<xf numFmtId="0" fontId="0" fillId="3" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="top"/></xf>
<xf numFmtId="164" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1" applyAlignment="1"><alignment horizontal="left" vertical="top"/></xf>
<xf numFmtId="164" fontId="0" fillId="3" borderId="1" xfId="0" applyNumberFormat="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="left" vertical="top"/></xf>
<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="4" fillId="4" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="top"/></xf>
<xf numFmtId="164" fontId="4" fillId="4" borderId="1" xfId="0" applyNumberFormat="1" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="left" vertical="top"/></xf>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
<dxfs count="0"/><tableStyles count="0" defaultTableStyle="TableStyleMedium2" defaultPivotStyle="PivotStyleLight16"/>
</styleSheet>
"@
        & $addText 'xl/styles.xml' $styles

        # Worksheets (streamed straight into the zip to keep memory low)
        for ($i = 0; $i -lt $Sheets.Count; $i++) {
            Write-Host "  Writing sheet '$($Sheets[$i].Name)' ($(if ($Sheets[$i].Rows) { $Sheets[$i].Rows.Count } else { 0 }) rows)..."
            $entry = $zip.CreateEntry("xl/worksheets/sheet$($i+1).xml", $lvl)
            $sw = New-Object System.IO.StreamWriter($entry.Open(), $enc, 65536)
            try { Write-XlsxSheet -Writer $sw -Sheet $Sheets[$i] -Selected ($i -eq 0) } finally { $sw.Dispose() }
        }
    }
    finally {
        $zip.Dispose()
        $fs.Dispose()
    }
    return $Path
}
#endregion

#region ======================== AD HELPERS ========================

$script:dnIndex      = @{}   # DistinguishedName -> info hashtable (case-insensitive)
$script:dnsToNetbios = @{}
$script:gcServer     = $null

function ConvertTo-YesNo($Value) {
    if ($null -eq $Value) { return '' }
    if ($Value) { 'Yes' } else { 'No' }
}

function Get-DomainFromDN([string]$DN) {
    $dns = (($DN -split '(?<!\\),') | Where-Object { $_ -like 'DC=*' } | ForEach-Object { $_.Substring(3) }) -join '.'
    if ($script:dnsToNetbios.ContainsKey($dns)) { return $script:dnsToNetbios[$dns] }
    return $dns
}

function Get-FriendlyType([string]$ObjectClass) {
    switch ($ObjectClass) {
        'user'                            { 'User' }
        'group'                           { 'Group' }
        'computer'                        { 'Computer' }
        'contact'                         { 'Contact' }
        'inetOrgPerson'                   { 'User (inetOrgPerson)' }
        'foreignSecurityPrincipal'        { 'Foreign Security Principal' }
        'msDS-ManagedServiceAccount'      { 'Managed Service Account' }
        'msDS-GroupManagedServiceAccount' { 'Group Managed Service Account' }
        default                           { $ObjectClass }
    }
}

function Resolve-MemberDN {
    # Returns info about any DN (user, group, computer, contact, FSP...). Cached.
    param([string]$DN, [string]$Server)
    if ([string]::IsNullOrEmpty($DN)) { return $null }
    if ($script:dnIndex.ContainsKey($DN)) { return $script:dnIndex[$DN] }

    $info = $null
    foreach ($srv in @($Server, $script:gcServer)) {
        if (-not $srv) { continue }
        try {
            $o = Get-ADObject -Identity $DN -Server $srv -Properties sAMAccountName, description, userAccountControl, groupType -ErrorAction Stop
            $cls  = [string]$o.ObjectClass
            $name = $o.Name
            $dom  = Get-DomainFromDN $DN
            if ($cls -eq 'foreignSecurityPrincipal') {
                try {
                    $name = (New-Object System.Security.Principal.SecurityIdentifier($o.Name)).Translate([System.Security.Principal.NTAccount]).Value
                    if ($name -match '^(.+?)\\') { $dom = $Matches[1] }
                } catch { $name = $o.Name; $dom = '(external / unresolved)' }
            }
            $enabled = ''
            if ($null -ne $o.userAccountControl) { $enabled = ConvertTo-YesNo (-not ([int]$o.userAccountControl -band 2)) }
            $scope = ''; $cat = ''
            if ($cls -eq 'group' -and $null -ne $o.groupType) {
                $gt = [int64]$o.groupType
                $scope = if ($gt -band 2) { 'Global' } elseif ($gt -band 4) { 'DomainLocal' } elseif ($gt -band 8) { 'Universal' } else { '' }
                $cat   = if ($gt -band [int64]2147483648) { 'Security' } else { 'Distribution' }
            }
            $info = @{
                Type        = Get-FriendlyType $cls
                Name        = $name
                Sam         = [string]$o.sAMAccountName
                Domain      = $dom
                Description = [string]($o.description -join ' ')
                Enabled     = $enabled
                Scope       = $scope
                Category    = $cat
            }
            break
        } catch { }
    }
    if (-not $info) {
        $cn = (($DN -split '(?<!\\),')[0] -replace '^(CN|OU)=', '') -replace '\\(.)', '$1'
        $info = @{ Type = 'Unknown'; Name = $cn; Sam = ''; Domain = (Get-DomainFromDN $DN); Description = ''; Enabled = ''; Scope = ''; Category = '' }
    }
    $script:dnIndex[$DN] = $info
    return $info
}

function Get-OUPath([string]$CanonicalName) {
    if ([string]::IsNullOrEmpty($CanonicalName)) { return '' }
    $i = $CanonicalName.LastIndexOf('/')
    if ($i -gt 0) { return $CanonicalName.Substring(0, $i) }
    return $CanonicalName
}
#endregion

#region ======================== COLLECT AD DATA ========================

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "The ActiveDirectory PowerShell module is not available. Run this on a Domain Controller or install RSAT: Install-WindowsFeature RSAT-AD-PowerShell"
    exit 1
}

if (-not $OutputPath) {
    $desk = [Environment]::GetFolderPath('Desktop')
    if (-not $desk -or -not (Test-Path $desk)) { $desk = $PWD.Path }
    $OutputPath = Join-Path $desk ("AD_Users_Groups_{0:yyyyMMdd_HHmm}.xlsx" -f (Get-Date))
}
if ($OutputPath -notmatch '\.xlsx$') { $OutputPath += '.xlsx' }

$domainList = if ($AllForestDomains) { @((Get-ADForest).Domains) }
              elseif ($Domain)      { @($Domain) }
              else                  { @((Get-ADDomain).DNSRoot) }

try {
    $gc = Get-ADDomainController -Discover -Service GlobalCatalog -ErrorAction Stop
    $script:gcServer = "$(@($gc.HostName)[0]):3268"
} catch { Write-Verbose 'No Global Catalog discovered; cross-domain members will be resolved from their DN only.' }

$userProps  = 'SamAccountName','DisplayName','GivenName','Surname','UserPrincipalName','Description',
              'EmailAddress','Title','Department','Company','Office','Manager','Enabled','LockedOut',
              'PasswordNeverExpires','PasswordExpired','LastLogonDate','PasswordLastSet',
              'AccountExpirationDate','whenCreated','MemberOf','PrimaryGroupID','CanonicalName'
$groupProps = 'SamAccountName','Description','GroupScope','GroupCategory','ManagedBy','Members',
              'whenCreated','CanonicalName','mail'

$domains = New-Object System.Collections.Generic.List[object]

# Phase 1 - pull all users and groups from every domain and index them
foreach ($d in $domainList) {
    Write-Host "Collecting users and groups from domain '$d'..." -ForegroundColor Cyan
    try {
        $adDomain = Get-ADDomain -Server $d -ErrorAction Stop
        $server   = $adDomain.PDCEmulator
        $users    = @(Get-ADUser  -Server $server -Filter * -Properties $userProps  -ResultPageSize 1000 -ErrorAction Stop)
        $groups   = @(Get-ADGroup -Server $server -Filter * -Properties $groupProps -ResultPageSize 1000 -ErrorAction Stop)
    } catch {
        Write-Warning "Skipping domain '$d': $($_.Exception.Message)"
        continue
    }
    $nb = $adDomain.NetBIOSName
    $script:dnsToNetbios[$adDomain.DNSRoot] = $nb
    Write-Host ("  {0} users, {1} groups found (queried {2})" -f $users.Count, $groups.Count, $server)

    $groupsByRid = @{}
    foreach ($g in $groups) {
        $script:dnIndex[$g.DistinguishedName] = @{
            Type = 'Group'; Name = $g.Name; Sam = $g.SamAccountName; Domain = $nb
            Description = [string]$g.Description; Enabled = ''
            Scope = [string]$g.GroupScope; Category = [string]$g.GroupCategory
        }
        $groupsByRid[$g.SID.Value.Split('-')[-1]] = $g
    }
    foreach ($u in $users) {
        $script:dnIndex[$u.DistinguishedName] = @{
            Type = 'User'; Name = $u.Name; Sam = $u.SamAccountName; Domain = $nb
            Description = [string]$u.Description; Enabled = (ConvertTo-YesNo $u.Enabled)
            Scope = ''; Category = ''
        }
    }
    $domains.Add([pscustomobject]@{
        DNS = $adDomain.DNSRoot; NetBIOS = $nb; Server = $server
        Users = $users; Groups = $groups; GroupsByRid = $groupsByRid
    })
}

if ($domains.Count -eq 0) { Write-Error 'No domain data could be collected.'; exit 1 }

# Phase 2 - build the rows for each sheet
$userRows    = New-Object System.Collections.Generic.List[object]
$mapRows     = New-Object System.Collections.Generic.List[object]
$groupRows   = New-Object System.Collections.Generic.List[object]
$summaryRows = New-Object System.Collections.Generic.List[object]

foreach ($dom in $domains) {
    $primaryMembers = @{}   # group DN -> list of user DNs that have it as primary group
    $total = $dom.Users.Count; $n = 0

    # ---------- Users ----------
    foreach ($u in ($dom.Users | Sort-Object SamAccountName)) {
        $n++
        if ($n % 200 -eq 0 -or $n -eq $total) {
            Write-Progress -Activity "Processing users in $($dom.DNS)" -Status "$n of $total" -PercentComplete ([math]::Min(100, $n / [math]::Max($total,1) * 100))
        }
        $memberships = New-Object System.Collections.Generic.List[object]

        $pg = $dom.GroupsByRid["$($u.PrimaryGroupID)"]
        if ($pg) {
            $memberships.Add(@{ Info = $script:dnIndex[$pg.DistinguishedName]; Kind = 'Primary Group' })
            if (-not $primaryMembers.ContainsKey($pg.DistinguishedName)) {
                $primaryMembers[$pg.DistinguishedName] = New-Object System.Collections.Generic.List[string]
            }
            $primaryMembers[$pg.DistinguishedName].Add($u.DistinguishedName)
        }
        foreach ($gdn in $u.MemberOf) {
            $memberships.Add(@{ Info = (Resolve-MemberDN $gdn $dom.Server); Kind = 'Direct' })
        }
        $memberships = @($memberships | Sort-Object { $_.Info.Name })

        $groupNames = ($memberships | ForEach-Object {
            if ($_.Info.Domain -and $_.Info.Domain -ne $dom.NetBIOS) { "$($_.Info.Domain)\$($_.Info.Name)" } else { $_.Info.Name }
        }) -join '; '

        $mgr = if ($u.Manager) { (Resolve-MemberDN $u.Manager $dom.Server).Name } else { '' }
        $disabled = -not $u.Enabled

        $userRows.Add(@{
            Domain = $dom.NetBIOS; DomainDNS = $dom.DNS; Sam = $u.SamAccountName; DisplayName = $u.DisplayName
            Description = $u.Description; Enabled = (ConvertTo-YesNo $u.Enabled)
            GivenName = $u.GivenName; Surname = $u.Surname; UPN = $u.UserPrincipalName; Email = $u.EmailAddress
            Title = $u.Title; Department = $u.Department; Company = $u.Company; Office = $u.Office; Manager = $mgr
            LockedOut = (ConvertTo-YesNo $u.LockedOut); PwdNeverExpires = (ConvertTo-YesNo $u.PasswordNeverExpires)
            PwdExpired = (ConvertTo-YesNo $u.PasswordExpired)
            LastLogon = $u.LastLogonDate; PwdLastSet = $u.PasswordLastSet; Expires = $u.AccountExpirationDate
            Created = $u.whenCreated; GroupCount = $memberships.Count; Groups = $groupNames
            OU = (Get-OUPath $u.CanonicalName); DN = $u.DistinguishedName
            _warn = $disabled
        })

        if ($memberships.Count -eq 0) {
            $mapRows.Add(@{ Domain = $dom.NetBIOS; Sam = $u.SamAccountName; DisplayName = $u.DisplayName
                Description = $u.Description; Enabled = (ConvertTo-YesNo $u.Enabled); GroupName = '(no groups)'
                _band = $u.DistinguishedName; _warn = $disabled })
        }
        foreach ($m in $memberships) {
            $mapRows.Add(@{
                Domain = $dom.NetBIOS; Sam = $u.SamAccountName; DisplayName = $u.DisplayName
                Description = $u.Description; Enabled = (ConvertTo-YesNo $u.Enabled)
                GroupName = $m.Info.Name; GroupDomain = $m.Info.Domain; GroupScope = $m.Info.Scope
                GroupCategory = $m.Info.Category; GroupDescription = $m.Info.Description; Membership = $m.Kind
                _band = $u.DistinguishedName; _warn = $disabled
            })
        }
    }
    Write-Progress -Activity "Processing users in $($dom.DNS)" -Completed

    # ---------- Groups & members ----------
    $total = $dom.Groups.Count; $n = 0; $empty = 0
    foreach ($g in ($dom.Groups | Sort-Object Name)) {
        $n++
        if ($n % 50 -eq 0 -or $n -eq $total) {
            Write-Progress -Activity "Processing groups in $($dom.DNS)" -Status "$n of $total" -PercentComplete ([math]::Min(100, $n / [math]::Max($total,1) * 100))
        }
        $members = New-Object System.Collections.Generic.List[object]
        foreach ($mdn in $g.Members) {
            $members.Add(@{ Info = (Resolve-MemberDN $mdn $dom.Server); DN = $mdn; Kind = 'Direct' })
        }
        if ($primaryMembers.ContainsKey($g.DistinguishedName)) {
            foreach ($udn in $primaryMembers[$g.DistinguishedName]) {
                $members.Add(@{ Info = $script:dnIndex[$udn]; DN = $udn; Kind = 'Primary Group' })
            }
        }
        $mgdBy = if ($g.ManagedBy) { (Resolve-MemberDN $g.ManagedBy $dom.Server).Name } else { '' }

        $base = @{
            Domain = $dom.NetBIOS; GroupName = $g.Name; GroupScope = [string]$g.GroupScope
            GroupCategory = [string]$g.GroupCategory; GroupDescription = $g.Description; GroupEmail = $g.mail
            ManagedBy = $mgdBy; MemberCount = $members.Count; GroupOU = (Get-OUPath $g.CanonicalName)
            _band = $g.DistinguishedName
        }
        if ($members.Count -eq 0) {
            $empty++
            $row = $base.Clone(); $row.MemberName = '(no members)'
            $groupRows.Add($row)
            continue
        }
        foreach ($m in ($members | Sort-Object { $_.Info.Type }, { $_.Info.Name })) {
            $row = $base.Clone()
            $row.MemberName        = $m.Info.Name
            $row.MemberSam         = $m.Info.Sam
            $row.MemberType        = $m.Info.Type
            $row.MemberDomain      = $m.Info.Domain
            $row.MemberDescription = $m.Info.Description
            $row.MemberEnabled     = $m.Info.Enabled
            $row.Membership        = $m.Kind
            $row.MemberDN          = $m.DN
            $row._warn             = ($m.Info.Enabled -eq 'No')
            $groupRows.Add($row)
        }
    }
    Write-Progress -Activity "Processing groups in $($dom.DNS)" -Completed

    $enabledCount = @($dom.Users | Where-Object { $_.Enabled }).Count
    $secCount     = @($dom.Groups | Where-Object { [string]$_.GroupCategory -eq 'Security' }).Count
    $summaryRows.Add(@{
        DomainDNS = $dom.DNS; Domain = $dom.NetBIOS; Users = $dom.Users.Count; Enabled = $enabledCount
        Disabled = $dom.Users.Count - $enabledCount; Groups = $dom.Groups.Count; Security = $secCount
        Distribution = $dom.Groups.Count - $secCount; Empty = $empty; Server = $dom.Server
    })
}

if ($summaryRows.Count -gt 1) {
    $t = @{ DomainDNS = 'ALL DOMAINS'; Domain = ''; Server = '' }
    foreach ($k in 'Users','Enabled','Disabled','Groups','Security','Distribution','Empty') {
        $t[$k] = ($summaryRows | ForEach-Object { $_[$k] } | Measure-Object -Sum).Sum
    }
    $summaryRows.Add($t)
}
#endregion

#region ======================== BUILD WORKBOOK ========================

$stamp    = Get-Date
$who      = "$env:USERDOMAIN\$env:USERNAME"
$domText  = ($domains | ForEach-Object { "$($_.NetBIOS) ($($_.DNS))" }) -join ', '
$subtitle = "Domain(s): $domText   |   Generated: {0:yyyy-MM-dd HH:mm} by $who on $env:COMPUTERNAME" -f $stamp

$sheets = @(
    @{
        Name = 'Summary'; TabColor = 'FF1F4E78'
        Title = 'Active Directory Users & Groups Report'; Subtitle = $subtitle
        Columns = @(
            @{ Header = 'Domain (DNS)';        Key = 'DomainDNS' }
            @{ Header = 'Domain (NetBIOS)';    Key = 'Domain' }
            @{ Header = 'Total Users';         Key = 'Users';        Type = 'Number' }
            @{ Header = 'Enabled Users';       Key = 'Enabled';      Type = 'Number' }
            @{ Header = 'Disabled Users';      Key = 'Disabled';     Type = 'Number' }
            @{ Header = 'Total Groups';        Key = 'Groups';       Type = 'Number' }
            @{ Header = 'Security Groups';     Key = 'Security';     Type = 'Number' }
            @{ Header = 'Distribution Groups'; Key = 'Distribution'; Type = 'Number' }
            @{ Header = 'Empty Groups';        Key = 'Empty';        Type = 'Number' }
            @{ Header = 'Domain Controller Queried'; Key = 'Server' }
        )
        Rows = $summaryRows
    }
    @{
        Name = 'Users'; TabColor = 'FF2E75B6'; FreezeColumns = 3; WarnKey = '_warn'
        Title = 'All Users and Their Groups'
        Subtitle = "$subtitle   |   Rows in red = disabled accounts"
        Columns = @(
            @{ Header = 'Domain';               Key = 'Domain' }
            @{ Header = 'Username';             Key = 'Sam' }
            @{ Header = 'Display Name';         Key = 'DisplayName' }
            @{ Header = 'Description';          Key = 'Description'; MaxWidth = 50 }
            @{ Header = 'Enabled';              Key = 'Enabled' }
            @{ Header = 'First Name';           Key = 'GivenName' }
            @{ Header = 'Last Name';            Key = 'Surname' }
            @{ Header = 'User Principal Name';  Key = 'UPN' }
            @{ Header = 'Email';                Key = 'Email' }
            @{ Header = 'Job Title';            Key = 'Title' }
            @{ Header = 'Department';           Key = 'Department' }
            @{ Header = 'Company';              Key = 'Company' }
            @{ Header = 'Office';               Key = 'Office' }
            @{ Header = 'Manager';              Key = 'Manager' }
            @{ Header = 'Locked Out';           Key = 'LockedOut' }
            @{ Header = 'Password Never Expires'; Key = 'PwdNeverExpires' }
            @{ Header = 'Password Expired';     Key = 'PwdExpired' }
            @{ Header = 'Last Logon';           Key = 'LastLogon';  Type = 'Date' }
            @{ Header = 'Password Last Set';    Key = 'PwdLastSet'; Type = 'Date' }
            @{ Header = 'Account Expires';      Key = 'Expires';    Type = 'Date' }
            @{ Header = 'Created';              Key = 'Created';    Type = 'Date' }
            @{ Header = 'Group Count';          Key = 'GroupCount'; Type = 'Number' }
            @{ Header = 'Member Of (Groups)';   Key = 'Groups'; MaxWidth = 80 }
            @{ Header = 'OU Path';              Key = 'OU'; MaxWidth = 60 }
            @{ Header = 'Distinguished Name';   Key = 'DN'; MaxWidth = 70 }
        )
        Rows = $userRows
    }
    @{
        Name = 'User Groups'; TabColor = 'FF548235'; FreezeColumns = 3; BandKey = '_band'; WarnKey = '_warn'
        Title = 'User Group Membership (one row per user / group)'
        Subtitle = "$subtitle   |   Rows in red = disabled accounts"
        Columns = @(
            @{ Header = 'Domain';            Key = 'Domain' }
            @{ Header = 'Username';          Key = 'Sam' }
            @{ Header = 'Display Name';      Key = 'DisplayName' }
            @{ Header = 'User Description';  Key = 'Description'; MaxWidth = 45 }
            @{ Header = 'Enabled';           Key = 'Enabled' }
            @{ Header = 'Group Name';        Key = 'GroupName' }
            @{ Header = 'Group Domain';      Key = 'GroupDomain' }
            @{ Header = 'Group Scope';       Key = 'GroupScope' }
            @{ Header = 'Group Type';        Key = 'GroupCategory' }
            @{ Header = 'Group Description'; Key = 'GroupDescription'; MaxWidth = 50 }
            @{ Header = 'Membership';        Key = 'Membership' }
        )
        Rows = $mapRows
    }
    @{
        Name = 'Groups & Members'; TabColor = 'FFC55A11'; FreezeColumns = 2; BandKey = '_band'; WarnKey = '_warn'
        Title = 'All Groups and Their Members'
        Subtitle = "$subtitle   |   Rows in red = disabled member accounts   |   'Primary Group' = membership via primaryGroupID (e.g. Domain Users)"
        Columns = @(
            @{ Header = 'Domain';             Key = 'Domain' }
            @{ Header = 'Group Name';         Key = 'GroupName' }
            @{ Header = 'Group Scope';        Key = 'GroupScope' }
            @{ Header = 'Group Type';         Key = 'GroupCategory' }
            @{ Header = 'Group Description';  Key = 'GroupDescription'; MaxWidth = 50 }
            @{ Header = 'Group Email';        Key = 'GroupEmail' }
            @{ Header = 'Managed By';         Key = 'ManagedBy' }
            @{ Header = 'Member Count';       Key = 'MemberCount'; Type = 'Number' }
            @{ Header = 'Member Name';        Key = 'MemberName' }
            @{ Header = 'Member Username';    Key = 'MemberSam' }
            @{ Header = 'Member Type';        Key = 'MemberType' }
            @{ Header = 'Member Domain';      Key = 'MemberDomain' }
            @{ Header = 'Member Description'; Key = 'MemberDescription'; MaxWidth = 50 }
            @{ Header = 'Member Enabled';     Key = 'MemberEnabled' }
            @{ Header = 'Membership';         Key = 'Membership' }
            @{ Header = 'Group OU Path';      Key = 'GroupOU'; MaxWidth = 50 }
            @{ Header = 'Member Distinguished Name'; Key = 'MemberDN'; MaxWidth = 70 }
        )
        Rows = $groupRows
    }
)

Write-Host 'Building Excel workbook...' -ForegroundColor Cyan
$file = New-XlsxWorkbook -Path $OutputPath -Sheets $sheets

Write-Host ''
Write-Host 'Export complete.' -ForegroundColor Green
Write-Host "  File          : $file"
Write-Host "  Users         : $($userRows.Count)"
Write-Host "  User/group map: $($mapRows.Count) rows"
Write-Host "  Group/member  : $($groupRows.Count) rows"
#endregion

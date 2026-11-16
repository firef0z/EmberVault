"""Lightweight generator for Office Open XML Spreadsheet (.xlsx) files without external dependencies."""

from __future__ import annotations

import io
import zipfile
from typing import Any
from xml.sax.saxutils import escape


def _col_letter(col_idx: int) -> str:
    """Convert 0-based column index to Excel column letter (A, B, ..., Z, AA, AB, etc.)."""
    res = ""
    col_idx += 1
    while col_idx > 0:
        col_idx, remainder = divmod(col_idx - 1, 26)
        res = chr(65 + remainder) + res
    return res


def generate_xlsx(
    headers: list[str], rows: list[list[Any]], sheet_name: str = "Audit Logs"
) -> bytes:
    """Build a valid .xlsx file in-memory using standard library zipfile and XML."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        # 1. [Content_Types].xml
        content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>"""
        z.writestr("[Content_Types].xml", content_types)

        # 2. _rels/.rels
        rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""
        z.writestr("_rels/.rels", rels)

        # 3. xl/_rels/workbook.xml.rels
        wb_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""
        z.writestr("xl/_rels/workbook.xml.rels", wb_rels)

        # 4. xl/workbook.xml
        safe_sheet_name = escape(sheet_name)
        workbook = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="{safe_sheet_name}" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>"""
        z.writestr("xl/workbook.xml", workbook)

        # 5. xl/styles.xml (Style 0: regular, Style 1: header bold with light background)
        styles = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2">
    <font><name val="Segoe UI"/><sz val="10"/></font>
    <font><b/><color rgb="FFFFFFFF"/><name val="Segoe UI"/><sz val="10"/></font>
  </fonts>
  <fills count="3">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF2563EB"/></patternFill></fill>
  </fills>
  <borders count="2">
    <border><left/><right/><top/><bottom/><diagonal/></border>
    <border>
      <left style="thin"><color rgb="FFE2E8F0"/></left>
      <right style="thin"><color rgb="FFE2E8F0"/></right>
      <top style="thin"><color rgb="FFE2E8F0"/></top>
      <bottom style="thin"><color rgb="FFE2E8F0"/></bottom>
    </border>
  </borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="2">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1"/>
    <xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>
  </cellXfs>
</styleSheet>"""
        z.writestr("xl/styles.xml", styles)

        # 6. xl/worksheets/sheet1.xml
        sheet_rows = []
        # Header row (s=1 for bold styling)
        header_cells = []
        for c_idx, h in enumerate(headers):
            ref = f"{_col_letter(c_idx)}1"
            val = escape(str(h))
            header_cells.append(f'<c r="{ref}" t="inlineStr" s="1"><is><t>{val}</t></is></c>')
        sheet_rows.append('<row r="1">' + "".join(header_cells) + "</row>")

        # Data rows
        for r_idx, row in enumerate(rows, start=2):
            row_cells = []
            for c_idx, cell in enumerate(row):
                ref = f"{_col_letter(c_idx)}{r_idx}"
                val = escape(str(cell) if cell is not None else "")
                row_cells.append(f'<c r="{ref}" t="inlineStr" s="0"><is><t>{val}</t></is></c>')
            sheet_rows.append(f'<row r="{r_idx}">' + "".join(row_cells) + "</row>")

        sheet_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    {"".join(sheet_rows)}
  </sheetData>
</worksheet>"""
        z.writestr("xl/worksheets/sheet1.xml", sheet_xml)

    return buf.getvalue()

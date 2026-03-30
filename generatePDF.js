// ============================================
// Generatepdf.js — Advanced Seating PDF
// ============================================

const PDFDocument = require("pdfkit");
const fs = require("fs");
const path = require("path");

// Path to the JNTU Anantapur logo — must sit in the same folder as this file
const LOGO_PATH = path.join(__dirname, "JNTUA_Logo.png");
const LOGO_W = 35;
const LOGO_H = 35;

async function generatePDF(res, db) {

  const halls        = await db.getAllHalls();
  const unallocated  = await db.getUnallocatedStudents();
  const logs         = await db.getLatestLog();
  const totalHalls   = halls.length;

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename=Seating_Chart_${Date.now()}.pdf`
  );

  const doc = new PDFDocument({
    margin: 30,
    size: "A4",
    layout: "landscape",
    autoFirstPage: false   // pages added manually so we control header/footer
  });

  doc.pipe(res);

  const LEFT         = 30;
  const RIGHT_MARGIN = 30;
  const BOTTOM       = 30;
  const FOOTER_H     = 20;   // reserved at page bottom

  // ── Pre-load logo buffer once so it renders on every page ────────────────
  let logoBuffer = null;
  try {
    logoBuffer = fs.readFileSync(LOGO_PATH);
  } catch (e) {
    console.warn("⚠ Logo not found at:", LOGO_PATH);
  }

  // ── Draw header for a hall page ──────────────────────────────────────────
  function drawPageHeader(hall, allocs) {
    const pageW  = doc.page.width;
    const textW  = pageW - LEFT - RIGHT_MARGIN - LOGO_W - 12;

    // Logo — right side
    if (logoBuffer) {
      doc.image(logoBuffer, pageW - RIGHT_MARGIN - LOGO_W, LEFT, {
        width: LOGO_W,
        height: LOGO_H
      });
    }

    // University name
    doc.fontSize(9)
      .font("Helvetica-Bold")
      .fillColor("black")
      .text(
        "JAWAHARLAL NEHRU TECHNOLOGICAL UNIVERSITY ANANTAPUR",
        LEFT, LEFT,
        { width: textW }
      );

    // Page title
    doc.fontSize(14)
      .font("Helvetica-Bold")
      .fillColor("black")
      .text("EXAMINATION SEATING ARRANGEMENT", LEFT, LEFT + 14, { width: textW });

    // Hall-specific details
    if (hall) {
      const occupied = allocs ? allocs.length : 0;
      doc.fontSize(8)
        .font("Helvetica")
        .fillColor("#111111")
        .text(
          `Hall ID: ${hall.hall_id}   Hall Name: ${hall.hall_name}   ` +
          `Capacity: ${hall.capacity}   Rows: ${hall.total_rows}   ` +
          `Cols: ${hall.total_cols}   Occupied Seats: ${occupied}   Unoccupied Seats: ${hall.capacity - occupied}`,
          LEFT, LEFT + 33,
          { width: textW }
        );
    } else {
      doc.fontSize(8)
        .font("Helvetica")
        .fillColor("#111111")
        .text("Unallocated Students", LEFT, LEFT + 33, { width: textW });
    }

    // Separator line
    const sepY = Math.max(LEFT + 60, LEFT + LOGO_H + 6);
    doc.moveTo(LEFT, sepY)
      .lineTo(pageW - RIGHT_MARGIN, sepY)
      .lineWidth(0.8)
      .strokeColor("black")
      .stroke();

    return sepY + 8;
  }

  // ── Draw footer with hall counter ────────────────────────────────────────
  function drawFooter(hallIndex) {
    const pageW   = doc.page.width;
    const pageH   = doc.page.height;
    const footerY = pageH - BOTTOM - 12;

    doc.moveTo(LEFT, footerY)
      .lineTo(pageW - RIGHT_MARGIN, footerY)
      .lineWidth(0.5)
      .strokeColor("black")
      .stroke();

    doc.fontSize(7)
      .font("Helvetica")
      .fillColor("#555555")
      .text("JNTUA CEA", LEFT, footerY + 3);

    const label = hallIndex <= totalHalls
      ? `Hall ${hallIndex} of ${totalHalls}`
      : "Unallocated List";

    doc.fontSize(7)
      .font("Helvetica-Bold")
      .fillColor("#222222")
      .text(label, LEFT, footerY + 3, {
        width: pageW - LEFT - RIGHT_MARGIN,
        align: "right"
      });
  }

  // ── State tracked for ensureSpace ────────────────────────────────────────
  let y                = 0;
  let _currentHall     = null;
  let _currentAllocs   = null;
  let _currentHallIdx  = 0;

  function ensureSpace(needed) {
    if (y + needed > doc.page.height - BOTTOM - FOOTER_H) {
      drawFooter(_currentHallIdx);
      doc.addPage();
      y = drawPageHeader(_currentHall, _currentAllocs);
    }
  }

  // ================= HALLS =================

  for (let hi = 0; hi < halls.length; hi++) {
    const hall      = halls[hi];
    const hallIndex = hi + 1;
    const allocs    = await db.getAllocationsByHall(hall.hall_id);

    _currentHall    = hall;
    _currentAllocs  = allocs;
    _currentHallIdx = hallIndex;

    doc.addPage();
    y = drawPageHeader(hall, allocs);

    // Build seat lookup map
    const seatMap = {};
    for (const a of allocs) {
      seatMap[`${a.seat_row}-${a.seat_col}`] = a;
    }

    const LABEL_W   = 25;
    const TOP_LBL_H = 16;
    const CELL_H    = 26;

    const usableWidth = doc.page.width - LEFT - RIGHT_MARGIN - LABEL_W - 2;
    const CELL_W      = Math.floor(usableWidth / hall.total_cols);

    // Column number headers
    doc.fontSize(7).font("Helvetica-Bold").fillColor("black");
    for (let c = 1; c <= hall.total_cols; c++) {
      const x = LEFT + LABEL_W + 2 + (c - 1) * CELL_W;
      doc.text(`C${c}`, x, y, { width: CELL_W - 2, align: "center" });
    }
    y += TOP_LBL_H;

    // Seat grid row by row
    for (let r = 1; r <= hall.total_rows; r++) {

      // Row label
      doc.fontSize(7)
        .font("Helvetica-Bold")
        .fillColor("black")
        .text(`R${r}`, LEFT -8, y + 10, { width: LABEL_W, align: "right" });

      // Cells
      for (let c = 1; c <= hall.total_cols; c++) {
        const x    = LEFT + LABEL_W + 2 + (c - 1) * CELL_W;
        const seat = seatMap[`${r}-${c}`];

        doc.rect(x, y, CELL_W - 2, CELL_H)
          .fillAndStroke("white", "black");

        if (seat) {
          doc.fontSize(6)
            .font("Helvetica-Bold")
            .fillColor("black")
            .text(seat.subject_code, x + 1, y + 4, {
              width: CELL_W - 4,
              align: "center"
            });

          doc.fontSize(5)
            .font("Helvetica")
            .fillColor("black")
            .text(seat.student_id, x + 1, y + 14, {
              width: CELL_W - 4,
              align: "center"
            });
        }
      }

      y += CELL_H + 2;

      // Page overflow within the same hall
      if (r < hall.total_rows && y + CELL_H > doc.page.height - BOTTOM - FOOTER_H) {
        drawFooter(hallIndex);
        doc.addPage();
        y = drawPageHeader(hall, allocs);

        doc.fontSize(7).font("Helvetica-Bold").fillColor("black");
        for (let c = 1; c <= hall.total_cols; c++) {
          const x = LEFT + LABEL_W + 2 + (c - 1) * CELL_W;
          doc.text(`C${c}`, x, y, { width: CELL_W - 2, align: "center" });
        }
        y += TOP_LBL_H;
      }
    }

    // ── Subject-wise summary table below seat grid ───────────────────────
    y += 10;

    const subjectMap = {};
    for (const a of allocs) {
      subjectMap[a.subject_code] = (subjectMap[a.subject_code] || 0) + 1;
    }

    const subjects   = Object.entries(subjectMap);
    const total      = allocs.length;
    const S_ROW_H    = 14;
    const S_COL1     = 160;   // Subject code column width
    const S_COL2     = 50;    // Count column width
    const S_TABLE_W  = S_COL1 + S_COL2;
    const S_LEFT     = LEFT + 27;  // shift summary table 20px right

    // If summary doesn't fit on current page, add new page
    const summaryHeight = (subjects.length + 1) * S_ROW_H + 10;
    if (y + summaryHeight > doc.page.height - BOTTOM - FOOTER_H) {
      drawFooter(hallIndex);
      doc.addPage();
      y = drawPageHeader(hall, allocs);
    }

    // Subject rows
    subjects.forEach(([code, count], i) => {
      const rowBg = i % 2 === 0 ? "#f5f5f5" : "white";
      doc.rect(S_LEFT, y, S_TABLE_W, S_ROW_H)
        .fillAndStroke(rowBg, "#bbbbbb");

      doc.fontSize(7).font("Helvetica").fillColor("#111111")
        .text(code, S_LEFT + 4, y + 3, { width: S_COL1 - 8, align: "left" });

      doc.fontSize(7).font("Helvetica-Bold").fillColor("#111111")
        .text(String(count).padStart(2, "0"), S_LEFT + S_COL1 + 4, y + 3, { width: S_COL2 - 8, align: "left" });

      // Vertical divider
      doc.moveTo(S_LEFT + S_COL1, y).lineTo(S_LEFT + S_COL1, y + S_ROW_H)
        .lineWidth(0.4).strokeColor("#bbbbbb").stroke();

      y += S_ROW_H;
    });

    // Total row
    doc.rect(S_LEFT, y, S_TABLE_W, S_ROW_H)
      .fillAndStroke("#dddddd", "#bbbbbb");

    doc.fontSize(7).font("Helvetica-Bold").fillColor("#111111")
      .text("Total", S_LEFT + 4, y + 3, { width: S_COL1 - 8, align: "left" });

    doc.fontSize(7).font("Helvetica-Bold").fillColor("#111111")
      .text(String(total).padStart(2, "0"), S_LEFT + S_COL1 + 4, y + 3, { width: S_COL2 - 8, align: "left" });

    doc.moveTo(S_LEFT + S_COL1, y).lineTo(S_LEFT + S_COL1, y + S_ROW_H)
      .lineWidth(0.4).strokeColor("#bbbbbb").stroke();

    y += S_ROW_H;

    drawFooter(hallIndex);
  }

  // ================= UNALLOCATED =================

  if (unallocated.length > 0) {
    _currentHall    = null;
    _currentAllocs  = null;
    _currentHallIdx = totalHalls + 1;

    doc.addPage();
    y = drawPageHeader(null, null);

    doc.fontSize(12)
      .font("Helvetica-Bold")
      .fillColor("red")
      .text("Unallocated Students", LEFT, y);
    doc.fillColor("black");
    y += 20;

    // Table config — totalTableW is sum of COL_W, not full page width
    const COL_W        = [40, 110, 180, 100];   // S.No | Student ID | Student Name | Department
    const totalTableW  = COL_W.reduce((a, b) => a + b, 0);
    const HEADERS      = ["S.No", "Student ID", "Student Name", "Department"];
    const ROW_H        = 20;
    const HEAD_H       = 22;

    // ── Draw table header ──────────────────────────────────────────────────
    function drawTableHeader() {
      doc.rect(LEFT, y, totalTableW, HEAD_H)
        .fillAndStroke("#222222", "#222222");

      let cx = LEFT;
      HEADERS.forEach((h, i) => {
        doc.fontSize(8)
          .font("Helvetica-Bold")
          .fillColor("white")
          .text(h, cx + 4, y + 6, { width: COL_W[i] - 8, align: "center" });
        cx += COL_W[i];
      });

      y += HEAD_H;
    }

    drawTableHeader();

    // ── Draw each student row ──────────────────────────────────────────────
    unallocated.forEach((u, idx) => {

      // Page overflow
      if (y + ROW_H > doc.page.height - BOTTOM - FOOTER_H) {
        drawFooter(totalHalls + 1);
        doc.addPage();
        y = drawPageHeader(null, null);

        doc.fontSize(12)
          .font("Helvetica-Bold")
          .fillColor("red")
          .text("UNALLOCATED STUDENTS (contd.)", LEFT, y);
        doc.fillColor("black");
        y += 20;

        drawTableHeader();
      }

      const rowBg = idx % 2 === 0 ? "#f9f9f9" : "white";

      doc.rect(LEFT, y, totalTableW, ROW_H)
        .fillAndStroke(rowBg, "#cccccc");

      const values = [
        String(idx + 1),
        u.student_id,
        u.student_name,
        u.subject_code
      ];

      let cx = LEFT;
      values.forEach((val, i) => {
        doc.fontSize(8)
          .font("Helvetica")
          .fillColor("#111111")
          .text(val, cx + 4, y + 5, { width: COL_W[i] - 8, align: "center" });
        cx += COL_W[i];
      });

      // Vertical column dividers
      cx = LEFT;
      COL_W.slice(0, -1).forEach(w => {
        cx += w;
        doc.moveTo(cx, y).lineTo(cx, y + ROW_H)
          .lineWidth(0.4).strokeColor("#cccccc").stroke();
      });

      y += ROW_H;
    });

    // Bottom border of table
    doc.moveTo(LEFT, y).lineTo(LEFT + totalTableW, y)
      .lineWidth(0.8).strokeColor("#222222").stroke();

    drawFooter(totalHalls + 1);
  }

  doc.end();
}

module.exports = { generatePDF };

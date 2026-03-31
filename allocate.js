/**
 * Smart Exam Seating Allocation Algorithm (Balanced + Flexible)
 */

function runAllocationAlgorithm(groupedStudents, halls, deptOrder = null) {

  const allocations = [];
  const unallocated = [];
  const summary = [];
  const hallAssignments = {};

  // ── Filter invalid students ───────────────────────────────
  const PLACEHOLDERS = new Set(['self report','n/a','na','-','null','none','absent','']);

  function isValid(s) {
    if (!s.student_id) return false;
    const name = String(s.student_name || '').toLowerCase().trim();
    return !PLACEHOLDERS.has(name);
  }

  // ── Departments order ─────────────────────────────────────
  const allDepts = deptOrder
    ? deptOrder.filter(d => groupedStudents[d])
    : Object.keys(groupedStudents);

  // ── Sort students ─────────────────────────────────────────
  function rollKey(s) {
    const id = String(s.roll_no ?? s.student_id ?? '');
    const m = id.match(/^(.*?)(\d+)$/);
    return m ? { p: m[1], n: +m[2] } : { p: id, n: 0 };
  }

  const queues = {};
  for (const dept of allDepts) {
    queues[dept] = (groupedStudents[dept] || [])
      .filter(isValid)
      .map(s => ({ ...s }))
      .sort((a, b) => {
        const ka = rollKey(a), kb = rollKey(b);
        if (ka.p !== kb.p) return ka.p.localeCompare(kb.p);
        return ka.n - kb.n;
      });
  }

  // ── Process each hall ─────────────────────────────────────
  for (const hall of halls) {

    const result = seatHallSmart(hall, allDepts, queues);

    allocations.push(...result.allocations);

    // summary
    const deptCounts = {};
    for (const a of result.allocations) {
      deptCounts[a.dept_code] = (deptCounts[a.dept_code] || 0) + 1;
    }

    summary.push({
      hall_id: hall.hall_id,
      hall_name: hall.hall_name,
      total: result.allocations.length,
      dept_counts: deptCounts,
      violations: result.violations
    });

    // first hall assignment
    for (const dept of Object.keys(deptCounts)) {
      if (hallAssignments[dept] === undefined) {
        hallAssignments[dept] = hall.hall_id;
      }
    }
  }

  // ── Unallocated ───────────────────────────────────────────
  for (const dept of allDepts) {
    for (const s of queues[dept]) {
      unallocated.push({
        student_id: s.student_id,
        student_name: s.student_name,
        dept_code: dept,
        reason: 'No capacity'
      });
    }
  }

  const totalViolations = summary.reduce((s, h) => s + h.violations, 0);

  return { allocations, unallocated, violations: totalViolations, hallAssignments, summary };
}


// ============================================================
// Smart Hall Allocation
// ============================================================

function seatHallSmart(hall, allDepts, queues) {

  const allocations = [];
  const seatMap = {};

  const R = hall.total_rows;
  const C = hall.total_cols;

  // ── Build seat priority (structured) ──────────────────────
  const seats = [];

  const numGroups = Math.floor(C / 2);

  for (let gi = 0; gi < numGroups; gi++) {
    for (let parity = 0; parity < 2; parity++) {

      for (const col of [gi + 1, gi + 1 + numGroups]) {
        for (let row = 1 + parity; row <= R; row += 2) {
          seats.push([row, col]);
        }
      }

    }
  }

  // ── Adjacency check ───────────────────────────────────────
  function hasConflict(row, col, dept) {
    const dirs = [
      [0,1],[1,0],[1,1],[1,-1],
      [0,-1],[-1,0],[-1,-1],[-1,1]
    ];

    for (const [dr, dc] of dirs) {
      const key = `${row+dr},${col+dc}`;
      if (seatMap[key] && seatMap[key] === dept) return true;
    }
    return false;
  }

  // ── Fill seats ────────────────────────────────────────────
  for (const [row, col] of seats) {

    // sort depts by remaining students (largest first)
    const sorted = [...allDepts].sort(
      (a, b) => queues[b].length - queues[a].length
    );

    let placed = false;

    // try safe placement first
    for (const dept of sorted) {

      if (queues[dept].length === 0) continue;

      if (!hasConflict(row, col, dept)) {

        const student = queues[dept].shift();

        seatMap[`${row},${col}`] = dept;

        allocations.push({
          student_id: student.student_id,
          student_name: student.student_name || '',
          dept_code: dept,
          subject_code: student.subject_code || dept,
          hall_id: hall.hall_id,
          seat_row: row,
          seat_col: col,
          seat_label: `R${row}C${col}`
        });

        placed = true;
        break;
      }
    }

    // fallback (ignore adjacency if needed)
    if (!placed) {
      for (const dept of sorted) {
        if (queues[dept].length > 0) {

          const student = queues[dept].shift();

          seatMap[`${row},${col}`] = dept;

          allocations.push({
            student_id: student.student_id,
            student_name: student.student_name || '',
            dept_code: dept,
            subject_code: student.subject_code || dept,
            hall_id: hall.hall_id,
            seat_row: row,
            seat_col: col,
            seat_label: `R${row}C${col}`
          });

          break;
        }
      }
    }
  }

  return {
    allocations,
    violations: scan8Violations(seatMap, R, C)
  };
}


// ============================================================
// Violation checker
// ============================================================

function scan8Violations(seatMap, R, C) {

  let count = 0;

  const dirs = [[0,1],[1,0],[1,1],[1,-1]];

  for (let r = 1; r <= R; r++) {
    for (let c = 1; c <= C; c++) {

      const here = seatMap[`${r},${c}`];
      if (!here) continue;

      for (const [dr, dc] of dirs) {
        const nr = r + dr, nc = c + dc;

        if (nr < 1 || nr > R || nc < 1 || nc > C) continue;

        const there = seatMap[`${nr},${nc}`];
        if (there && there === here) count++;
      }
    }
  }

  return count;
}


// ============================================================

module.exports = { runAllocationAlgorithm };

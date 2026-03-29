
/**
 * @param {Object} groupedStudents  { dept_code: [student, ...] }
 *   student = { student_id, student_name, dept_code, roll_no? }
 *
 * @param {Array}  halls
 *   [{ hall_id, hall_name, capacity, total_rows, total_cols }]
 *   total_cols must be even.
 *
 * @param {Array}  [deptOrder]
 *   Fixed dept ordering — controls which dept goes in which column slot.
 *   MUST stay the same for all halls (changing it causes roll-number skips).
 *   Example: ['Civil', 'EEE', 'Mech', 'ECE', 'CSE', 'Chemical']
 *
 * @returns {{ allocations, unallocated, violations, hallAssignments, summary }}
 */
function runAllocationAlgorithm(groupedStudents, halls, deptOrder = null) {
  const allocations     = [];
  const unallocated     = [];
  const hallAssignments = {};
  const summary         = [];

  // ── Placeholder names to filter out ───────────────────────────────────────
  const PLACEHOLDERS = new Set(['self report', 'n/a', 'na', '-', 'null', 'none', 'absent', '']);

  function isValidStudent(s) {
    if (!s.student_id || String(s.student_id).trim() === '') return false;
    const name = String(s.student_name || '').trim().toLowerCase();
    return !PLACEHOLDERS.has(name);
  }

  // ── Step 1: Fix dept order — NEVER changes between halls ──────────────────
  const allDepts = deptOrder
    ? [...deptOrder].filter(d => groupedStudents[d])
    : Object.keys(groupedStudents).sort();

  // ── Step 2: Sort students by roll number, filtering placeholders ───────────
  //    Roll IDs like "24001A0557": split into prefix + numeric tail for sorting.
  //    Gaps in numbers = valid enrollment gaps, not algorithm errors.
  function rollSortKey(s) {
    const id = String(s.roll_no ?? s.student_id ?? '');
    const m  = id.match(/^(.*?)(\d+)$/);
    return m ? { prefix: m[1], num: parseInt(m[2], 10) } : { prefix: id, num: 0 };
  }

  const queues = {};
  for (const dept of allDepts) {
    queues[dept] = (groupedStudents[dept] || [])
      .filter(isValidStudent)
      .map(s => ({ ...s }))
      .sort((a, b) => {
        const ka = rollSortKey(a), kb = rollSortKey(b);
        if (ka.prefix !== kb.prefix) return ka.prefix.localeCompare(kb.prefix);
        return ka.num - kb.num;
      });
  }

  // ── Step 3: Per-hall quotas — fixed 8 per dept, last hall takes rest ────────
  //
  //    Every hall (except the last) gets exactly SEATS_PER_DEPT students
  //    per dept — matching the column capacity of a full 8-row hall.
  //    The last hall takes whatever remains for each dept naturally.
  //
  //    SEATS_PER_DEPT = 8  (4 odd-row seats + 4 even-row seats per column pair)
  //    Override per hall using hall.total_rows if rooms differ in size.

  const SEATS_PER_DEPT = 8;
  const N = halls.length;
  const quotas = halls.map(() => ({}));

  for (const dept of allDepts) {
    let remaining = queues[dept].length;

    for (let i = 0; i < N; i++) {
      if (remaining === 0) { quotas[i][dept] = 0; continue; }

      let quota;
      if (i < N - 1) {
        // Fixed 8 per dept (or hall's own row count if different room size)
        const fixed = halls[i].total_rows; // = 8 for standard halls
        quota = Math.min(fixed, remaining);
      } else {
        // Last hall: take everything left
        quota = remaining;
      }

      quotas[i][dept] = quota;
      remaining      -= quota;
    }
  }

  // ── Step 4: Place students hall by hall ───────────────────────────────────
  for (let hi = 0; hi < halls.length; hi++) {
    const hall      = halls[hi];
    const hallQuota = quotas[hi];

    for (const dept of allDepts) {
      if (hallQuota[dept] > 0 && hallAssignments[dept] === undefined) {
        hallAssignments[dept] = hall.hall_id;
      }
    }

    const result = seatHall(hall, allDepts, queues, hallQuota);
    allocations.push(...result.allocations);

    const deptCounts = {};
    for (const a of result.allocations) {
      deptCounts[a.dept_code] = (deptCounts[a.dept_code] || 0) + 1;
    }
    summary.push({
      hall_id:     hall.hall_id,
      hall_name:   hall.hall_name,
      total:       result.allocations.length,
      dept_counts: deptCounts,
      violations:  result.violations,
    });
  }

  // ── Step 5: Remaining in queues = truly unallocated ───────────────────────
  for (const dept of allDepts) {
    for (const s of queues[dept]) {
      unallocated.push({
        student_id:   s.student_id,
        student_name: s.student_name || '',
        dept_code:    dept,
        subject_code: s.subject_code || dept,
        reason:       'No remaining hall capacity',
      });
    }
    queues[dept] = [];
  }

  const totalViolations = summary.reduce((sum, h) => sum + h.violations, 0);
  return { allocations, unallocated, violations: totalViolations, hallAssignments, summary };
}


// ============================================================
// seatHall — places students in one hall
// ============================================================
function seatHall(hall, allDepts, queues, hallQuota) {
  const allocations = [];
  const R           = hall.total_rows;
  const C           = hall.total_cols;
  const numGroups   = Math.floor(C / 2);

  // Build seat list per dept slot: left col rows first, then right col rows
  const seatLists = {};
  for (let gi = 0; gi < numGroups; gi++) {
    for (let parity = 0; parity < 2; parity++) {
      const deptIdx = gi * 2 + parity;
      const seats   = [];
      for (const col of [gi + 1, gi + 1 + numGroups]) {
        for (let row = 1 + parity; row <= R; row += 2) {
          seats.push([row, col]);
        }
      }
      seatLists[deptIdx] = seats;
    }
  }

  const seatMap = {};

  for (let deptIdx = 0; deptIdx < allDepts.length && deptIdx < numGroups * 2; deptIdx++) {
    const dept = allDepts[deptIdx];
    if (!dept || !queues[dept]) continue;

    const allowed = hallQuota[dept] || 0;
    const seats   = seatLists[deptIdx] || [];
    let placed    = 0;

    for (const [row, col] of seats) {
      if (placed >= allowed)         break;
      if (queues[dept].length === 0) break;
      seatMap[`${row},${col}`] = { student: queues[dept].shift(), dept };
      placed++;
    }
  }

  // Emit in row-first display order
  for (let row = 1; row <= R; row++) {
    for (let col = 1; col <= C; col++) {
      const entry = seatMap[`${row},${col}`];
      if (!entry) continue;
      allocations.push({
        student_id:   entry.student.student_id,
        student_name: entry.student.student_name || '',
        dept_code:    entry.dept,
        subject_code: entry.student.subject_code || entry.dept,
        hall_id:      hall.hall_id,
        seat_row:     row,
        seat_col:     col,
        seat_label:   `R${row}C${col}`,
      });
    }
  }

  return { allocations, violations: scan8Violations(seatMap, R, C) };
}


// ============================================================
// scan8Violations — counts same-dept 8-directional adjacent pairs
// ============================================================
function scan8Violations(seatMap, R, C) {
  let count = 0;
  const dirs = [[0,1],[1,0],[1,1],[1,-1]];
  for (let row = 1; row <= R; row++) {
    for (let col = 1; col <= C; col++) {
      const here = seatMap[`${row},${col}`];
      if (!here) continue;
      for (const [dr, dc] of dirs) {
        const nr = row + dr, nc = col + dc;
        if (nr < 1 || nr > R || nc < 1 || nc > C) continue;
        const there = seatMap[`${nr},${nc}`];
        if (there && there.dept === here.dept) count++;
      }
    }
  }
  return count;
}


// ============================================================
module.exports = { runAllocationAlgorithm };


// ============================================================
// USAGE EXAMPLE
// ============================================================
/*

const groupedStudents = {
  'Civil':    [{ student_id: '24001A0101', dept_code: 'Civil' }, ...],
  'EEE':      [...],
  'Mech':     [...],
  'ECE':      [...],
  'CSE':      [...],      // more students than others — handled correctly now
  'Chemical': [...],
};

const halls = [
  { hall_id: '201', hall_name: 'Room 201', total_rows: 8, total_cols: 6, capacity: 48 },
  { hall_id: '202', hall_name: 'Room 202', total_rows: 8, total_cols: 6, capacity: 48 },
  // ...
  { hall_id: '209', hall_name: 'Room 209', total_rows: 8, total_cols: 6, capacity: 48 },
];

const deptOrder = ['Civil', 'EEE', 'Mech', 'ECE', 'CSE', 'Chemical'];

const { allocations, unallocated, violations, summary } =
  runAllocationAlgorithm(groupedStudents, halls, deptOrder);

console.log('Unallocated:', unallocated.length);  // → 0
console.log('Violations:',  violations);           // → 0

summary.forEach(h => console.log(h.hall_id, h.total, h.dept_counts));

*/

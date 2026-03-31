
/**
 * allocate_v13.js
 *
 * Changes from v12  (★ marks every modified / new section)
 * ─────────────────────────────────────────────────────────
 * ★ Step 3  — Dynamic quota calculation (Phase B)
 *     • Base quota = hall.total_rows (8 for standard halls)  [Phase A — unchanged]
 *     • After assigning base quotas, compute each hall's leftover capacity
 *     • Overflow departments get extra seats drawn from halls with unused capacity
 *     • Priority for extra seats: dept with most remaining students first
 *     • Future hall quotas are reduced by 1 for each extra seat awarded here
 *     • Last hall still takes everything left, as before
 *
 * ★ seatHall — Secondary fill-empty-seats pass
 *     • After the primary column-slot fill, a second pass scans every empty
 *       seat (row-by-row) and fills it from the dept queue with the most
 *       students left — subject to 8-directional non-adjacency check
 *     • Original column-slot logic is completely untouched
 *
 * scan8Violations — unchanged (already 8-directional in v12)
 */

/**
 * @param {Object} groupedStudents  { dept_code: [student, ...] }
 * @param {Array}  halls            [{ hall_id, hall_name, capacity, total_rows, total_cols }]
 * @param {Array}  [deptOrder]
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
    : Object.keys(groupedStudents);

  // ── Step 2: Sort students by roll number, filtering placeholders ───────────
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

  // ★ ── Step 3: Dynamic quota calculation ────────────────────────────────────
  const N = halls.length;
  const quotas = halls.map(() => ({}));

  // ── Phase A: base quotas (same as v12) ────────────────────────────────────
  for (const dept of allDepts) {
    let remaining = queues[dept].length;
    for (let i = 0; i < N; i++) {
      if (remaining === 0) { quotas[i][dept] = 0; continue; }
      let quota;
      if (i < N - 1) {
        const fixed = halls[i].total_rows;   // 8 for standard halls
        quota = Math.min(fixed, remaining);
      } else {
        quota = remaining;                   // last hall: take all
      }
      quotas[i][dept] = quota;
      remaining      -= quota;
    }
  }

  // ★ ── Phase B: redistribute spare capacity in non-last halls ──────────────
  //
  //  For each non-last hall, if hall.capacity > sum(quotas[i]), those free
  //  slots are given to whichever dept still has the most unallocated students.
  //  We balance the books by reducing that dept's quota in a future hall by 1.

  for (let i = 0; i < N - 1; i++) {
    const hallCap  = halls[i].capacity;
    let   hallUsed = Object.values(quotas[i]).reduce((s, v) => s + v, 0);
    let   freeSlots = hallCap - hallUsed;

    if (freeSlots <= 0) continue;

    while (freeSlots > 0) {
      // Compute how many students are still unassigned for each dept
      const remaining = {};
      for (const dept of allDepts) {
        let assigned = 0;
        for (let j = 0; j < N; j++) assigned += (quotas[j][dept] || 0);
        remaining[dept] = queues[dept].length - assigned;
      }

      // Pick dept with most remaining students (tie-break: alphabetical)
      const candidate = allDepts
        .filter(d => (remaining[d] || 0) > 0)
        .sort((a, b) => (remaining[b] || 0) - (remaining[a] || 0) || a.localeCompare(b))[0];

      if (!candidate) break;   // no dept has unassigned students

      // Award one extra seat in hall i
      quotas[i][candidate] = (quotas[i][candidate] || 0) + 1;
      freeSlots--;

      // Remove one seat from this dept in a future hall (last hall first)
      for (let j = N - 1; j > i; j--) {
        if ((quotas[j][candidate] || 0) > 0) {
          quotas[j][candidate]--;
          break;
        }
      }
    }
  }
  // ★ ── End Phase B ──────────────────────────────────────────────────────────

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

  // Build seat list per dept slot (unchanged from v12)
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

  // ── Primary pass: column-slot fill (unchanged from v12) ───────────────────
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

  // ★ ── Secondary pass: fill remaining empty seats ──────────────────────────
  //
  //  Scan every seat row-by-row. If the seat is still empty, find the dept
  //  with the most students left in its queue that would NOT create an
  //  8-directional same-dept adjacency at this position. Place that student.
  //
  //  This handles two scenarios:
  //    a) Dynamic quotas gave a dept more seats than its column slot can hold
  //    b) Fewer depts than column slots leave physical gaps

  function wouldViolate(row, col, dept) {
    for (let dr = -1; dr <= 1; dr++) {
      for (let dc = -1; dc <= 1; dc++) {
        if (dr === 0 && dc === 0) continue;
        const nr = row + dr, nc = col + dc;
        if (nr < 1 || nr > R || nc < 1 || nc > C) continue;
        const nb = seatMap[`${nr},${nc}`];
        if (nb && nb.dept === dept) return true;
      }
    }
    return false;
  }

  for (let row = 1; row <= R; row++) {
    for (let col = 1; col <= C; col++) {
      if (seatMap[`${row},${col}`]) continue;   // already filled

      // Best candidate: most students remaining, no 8-dir violation
      const candidate = allDepts
        .filter(d => queues[d] && queues[d].length > 0)
        .filter(d => !wouldViolate(row, col, d))
        .sort((a, b) => queues[b].length - queues[a].length || a.localeCompare(b))[0];

      if (!candidate) continue;

      seatMap[`${row},${col}`] = { student: queues[candidate].shift(), dept: candidate };
    }
  }
  // ★ ── End secondary pass ──────────────────────────────────────────────────

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
// (unchanged from v12)
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
  'CSE':      [...],      // large dept — gets extra seats via Phase B redistribution
  'Chemical': [...],      // small dept — spare quota donated to overflow depts
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

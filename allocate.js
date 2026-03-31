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

  // ── Step 3: Dynamic per-hall quotas ─────────────────────────────────────────
  //
  //    Strategy:
  //      a) Base quota per dept per hall = ceil(dept_total / N), capped at hall
  //         row capacity so no dept exceeds physical column space in a single hall.
  //      b) After base pass, compute each hall's used vs available seats.
  //         Redistribute surplus capacity to depts with the most remaining
  //         students, largest-first (deterministic, stable).
  //      c) Last hall always absorbs whatever is truly left — same as before.

  const HALL_COL_CAPACITY = halls[0].total_rows; // seats one dept can use per hall
  const N = halls.length;
  const quotas = halls.map(() => ({}));

  // ── 3a: Base pass — spread each dept evenly across halls ──────────────────
  for (const dept of allDepts) {
    let remaining = queues[dept].length;
    const basePerHall = Math.ceil(remaining / N);

    for (let i = 0; i < N; i++) {
      if (remaining === 0) { quotas[i][dept] = 0; continue; }

      let quota;
      if (i < N - 1) {
        quota = Math.min(basePerHall, HALL_COL_CAPACITY, remaining);
      } else {
        quota = remaining;
      }

      quotas[i][dept] = quota;
      remaining      -= quota;
    }
  }

  // ── 3b: Redistribution pass (all halls except last) ───────────────────────
  for (let i = 0; i < N - 1; i++) {
    const hall         = halls[i];
    const hallCapacity = hall.total_rows * hall.total_cols;
    const committed    = allDepts.reduce((sum, d) => sum + (quotas[i][d] || 0), 0);
    let freeSeats      = hallCapacity - committed;

    if (freeSeats <= 0) continue;

    const alreadyQuota = {};
    for (const dept of allDepts) {
      let assigned = 0;
      for (let j = 0; j <= i; j++) assigned += (quotas[j][dept] || 0);
      alreadyQuota[dept] = assigned;
    }

    const hungry = allDepts
      .map(dept => ({
        dept,
        need: queues[dept].length - alreadyQuota[dept],
      }))
      .filter(x => x.need > 0)
      .sort((a, b) => b.need - a.need);

    for (const { dept, need } of hungry) {
      if (freeSeats <= 0) break;
      const extra     = Math.min(need, freeSeats);
      quotas[i][dept] = (quotas[i][dept] || 0) + extra;
      freeSeats      -= extra;
    }
  }

  // ── 3c: Last hall — absorb everything truly remaining ─────────────────────
  for (const dept of allDepts) {
    let assigned = 0;
    for (let i = 0; i < N - 1; i++) assigned += (quotas[i][dept] || 0);
    const trueRemaining  = queues[dept].length - assigned;
    quotas[N - 1][dept]  = Math.max(0, trueRemaining);
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

  // Build seat list per dept slot
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

  // ── Fill pass: place overflow students into remaining empty seats ──────────
  //    Triggered when quota > column slot capacity (large dept overflow).
  //    Priority: dept with most remaining quota first.
  //    Seat order: row-by-row, left-to-right — preserves layout stability.

  const overflowDepts = allDepts
    .filter(d => queues[d] && queues[d].length > 0 && (hallQuota[d] || 0) > 0)
    .map(d => ({ dept: d, remaining: Math.min(queues[d].length, hallQuota[d]) }))
    .filter(x => x.remaining > 0)
    .sort((a, b) => b.remaining - a.remaining);

  if (overflowDepts.length > 0) {
    const emptySeats = [];
    for (let row = 1; row <= R; row++) {
      for (let col = 1; col <= C; col++) {
        if (!seatMap[`${row},${col}`]) emptySeats.push([row, col]);
      }
    }

    for (const [row, col] of emptySeats) {
      if (overflowDepts.length === 0) break;

      const top = overflowDepts[0];
      if (queues[top.dept].length === 0) { overflowDepts.shift(); continue; }

      seatMap[`${row},${col}`] = { student: queues[top.dept].shift(), dept: top.dept };
      top.remaining--;

      if (top.remaining <= 0 || queues[top.dept].length === 0) {
        overflowDepts.shift();
      }
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

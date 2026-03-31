/**
 * FINAL Exam Seating Allocation (STRICT + OPTIMIZED + OVERFLOW SAFE)
 */

function runAllocationAlgorithm(groupedStudents, halls, deptOrder = null) {

  const allocations = [];
  const unallocated = [];
  const summary = [];
  const hallAssignments = {};

  const PLACEHOLDERS = new Set(['self report','n/a','na','-','null','none','absent','']);

  function isValid(s) {
    if (!s.student_id) return false;
    const name = String(s.student_name || '').toLowerCase().trim();
    return !PLACEHOLDERS.has(name);
  }

  const allDepts = deptOrder
    ? deptOrder.filter(d => groupedStudents[d])
    : Object.keys(groupedStudents);

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

  for (const hall of halls) {

    const result = seatHallStrict(hall, allDepts, queues);

    improveAllocation(hall, result.seatMap, result.allocMap, queues);

    rebalanceOverflow(hall, result.seatMap, result.allocMap, queues);

    const finalAllocations = Object.values(result.allocMap);

    allocations.push(...finalAllocations);

    const deptCounts = {};
    for (const a of finalAllocations) {
      deptCounts[a.dept_code] = (deptCounts[a.dept_code] || 0) + 1;
    }

    summary.push({
      hall_id: hall.hall_id,
      hall_name: hall.hall_name,
      total: finalAllocations.length,
      dept_counts: deptCounts,
      violations: 0
    });

    for (const dept of Object.keys(deptCounts)) {
      if (hallAssignments[dept] === undefined) {
        hallAssignments[dept] = hall.hall_id;
      }
    }
  }

  for (const dept of allDepts) {
    for (const s of queues[dept]) {
      unallocated.push({
        student_id: s.student_id,
        student_name: s.student_name,
        dept_code: dept,
        reason: 'No safe seat (8-direction constraint)'
      });
    }
  }

  return { allocations, unallocated, violations: 0, hallAssignments, summary };
}


// ============================================================
// STRICT SEATING
// ============================================================

function seatHallStrict(hall, allDepts, queues) {

  const seatMap = {};
  const allocMap = {};

  const R = hall.total_rows;
  const C = hall.total_cols;

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

  function hasConflict(row, col, dept) {
    const dirs = [
      [0,1],[1,0],[1,1],[1,-1],
      [0,-1],[-1,0],[-1,-1],[-1,1]
    ];
    for (const [dr, dc] of dirs) {
      if (seatMap[`${row+dr},${col+dc}`] === dept) return true;
    }
    return false;
  }

  function getSortedDepts() {
    const arr = allDepts.filter(d => queues[d].length > 0);
    arr.sort((a, b) => queues[b].length - queues[a].length);

    for (let i = 0; i < Math.min(3, arr.length); i++) {
      const j = Math.floor(Math.random() * arr.length);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }

    return arr;
  }

  for (const [row, col] of seats) {

    const sorted = getSortedDepts();

    for (const dept of sorted) {

      if (!hasConflict(row, col, dept)) {

        const student = queues[dept].shift();
        const key = `${row},${col}`;

        seatMap[key] = dept;

        allocMap[key] = {
          student_id: student.student_id,
          student_name: student.student_name || '',
          dept_code: dept,
          subject_code: student.subject_code || dept,
          hall_id: hall.hall_id,
          seat_row: row,
          seat_col: col,
          seat_label: `R${row}C${col}`
        };

        break;
      }
    }
  }

  return { seatMap, allocMap };
}


// ============================================================
// IMPROVE (MOVE + SWAP)
// ============================================================

function improveAllocation(hall, seatMap, allocMap, queues) {

  const R = hall.total_rows;
  const C = hall.total_cols;

  function hasConflict(row, col, dept) {
    const dirs = [
      [0,1],[1,0],[1,1],[1,-1],
      [0,-1],[-1,0],[-1,-1],[-1,1]
    ];
    for (const [dr, dc] of dirs) {
      if (seatMap[`${row+dr},${col+dc}`] === dept) return true;
    }
    return false;
  }

  const emptySeats = [];
  for (let r = 1; r <= R; r++) {
    for (let c = 1; c <= C; c++) {
      if (!seatMap[`${r},${c}`]) emptySeats.push([r,c]);
    }
  }

  for (const dept of Object.keys(queues)) {

    let i = 0;

    while (i < queues[dept].length) {

      const student = queues[dept][i];
      let placed = false;

      // Direct
      for (let idx = 0; idx < emptySeats.length; idx++) {

        const [r,c] = emptySeats[idx];

        if (!hasConflict(r,c,dept)) {

          const key = `${r},${c}`;

          seatMap[key] = dept;
          allocMap[key] = {
            student_id: student.student_id,
            student_name: student.student_name || '',
            dept_code: dept,
            subject_code: student.subject_code || dept,
            hall_id: hall.hall_id,
            seat_row: r,
            seat_col: c,
            seat_label: `R${r}C${c}`
          };

          emptySeats.splice(idx,1);
          queues[dept].splice(i,1);

          placed = true;
          break;
        }
      }

      if (placed) continue;

      // Swap (fixed)
      for (const key of Object.keys(seatMap)) {

        const [r,c] = key.split(',').map(Number);
        const otherDept = seatMap[key];

        if (otherDept === dept) continue;

        delete seatMap[key];

        if (!hasConflict(r,c,dept)) {

          for (let idx = 0; idx < emptySeats.length; idx++) {

            const [r2,c2] = emptySeats[idx];

            if (!hasConflict(r2,c2,otherDept)) {

              const oldAlloc = allocMap[key];
              const newKey = `${r2},${c2}`;

              // move old
              seatMap[newKey] = otherDept;

              oldAlloc.seat_row = r2;
              oldAlloc.seat_col = c2;
              oldAlloc.seat_label = `R${r2}C${c2}`;

              allocMap[newKey] = oldAlloc;
              delete allocMap[key];

              // place new
              seatMap[key] = dept;

              allocMap[key] = {
                student_id: student.student_id,
                student_name: student.student_name || '',
                dept_code: dept,
                subject_code: student.subject_code || dept,
                hall_id: hall.hall_id,
                seat_row: r,
                seat_col: c,
                seat_label: `R${r}C${c}`
              };

              emptySeats.splice(idx,1);
              emptySeats.push([r,c]);

              queues[dept].splice(i,1);

              placed = true;
              break;
            }
          }

          if (placed) break;
        }

        seatMap[key] = otherDept;
      }

      if (!placed) i++;
    }
  }
}


// ============================================================
// OVERFLOW HANDLER
// ============================================================

function rebalanceOverflow(hall, seatMap, allocMap, queues) {

  const R = hall.total_rows;
  const C = hall.total_cols;

  function hasConflict(row, col, dept) {
    const dirs = [
      [0,1],[1,0],[1,1],[1,-1],
      [0,-1],[-1,0],[-1,-1],[-1,1]
    ];
    for (const [dr, dc] of dirs) {
      if (seatMap[`${row+dr},${col+dc}`] === dept) return true;
    }
    return false;
  }

  const heavyDepts = Object.keys(queues)
    .filter(d => queues[d].length > 0)
    .sort((a,b) => queues[b].length - queues[a].length);

  for (const dept of heavyDepts) {

    let tries = 0;

    while (queues[dept].length > 0 && tries < 200) {

      const student = queues[dept][0];
      let placed = false;

      for (let t = 0; t < 40; t++) {

        const r = Math.floor(Math.random() * R) + 1;
        const c = Math.floor(Math.random() * C) + 1;

        const key = `${r},${c}`;
        const existing = seatMap[key];

        if (!existing && !hasConflict(r,c,dept)) {

          seatMap[key] = dept;

          allocMap[key] = {
            student_id: student.student_id,
            student_name: student.student_name || '',
            dept_code: dept,
            subject_code: student.subject_code || dept,
            hall_id: hall.hall_id,
            seat_row: r,
            seat_col: c,
            seat_label: `R${r}C${c}`
          };

          queues[dept].shift();
          placed = true;
          break;
        }
      }

      if (!placed) break;
      tries++;
    }
  }
}


// ============================================================

module.exports = { runAllocationAlgorithm };

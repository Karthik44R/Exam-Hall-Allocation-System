/**
 * allocate_v14.js
 *
 * Multi-Algorithm Exam Hall Seating Allocator
 * ============================================
 * Runs MULTIPLE seating strategies per hall, scores each, picks the best.
 *
 * Algorithms tried per hall:
 *   1. ColumnSlot      — alternating-row column slots (original v13 logic)
 *   2. Checkerboard    — dept assigned by (row+col) % numDepts pattern
 *   3. DiagonalStripe  — dept assigned by diagonal index across the grid
 *   4. Serpentine      — snake-row fill, round-robin dept assignment
 *   5. BlockInterleave — fill in blocks of N cols, alternating dept each block
 *
 * Scoring (lower = better):
 *   score = violations * 1000 + emptySeats * 10 + deptClusterPenalty
 *
 * Last hall always uses 4-directional adjacency check only (no diagonals).
 * All other halls use 4-directional checks too (consistent & fair).
 *
 * @param {Object} groupedStudents  { dept_code: [student, ...] }
 *   student = { student_id, student_name, dept_code, roll_no? }
 *
 * @param {Array}  halls
 *   [{ hall_id, hall_name, capacity, total_rows, total_cols }]
 *
 * @param {Array}  [deptOrder]
 *   Fixed dept ordering — controls dept column priority.
 *
 * @returns {{ allocations, unallocated, violations, hallAssignments, summary, algorithmUsed }}
 */
function runAllocationAlgorithm(groupedStudents, halls, deptOrder = null) {

  const allocations     = [];
  const unallocated     = [];
  const hallAssignments = {};
  const summary         = [];
  const algorithmUsed   = {};

  // ── Placeholder filter ─────────────────────────────────────────────────────
  const PLACEHOLDERS = new Set(['self report', 'n/a', 'na', '-', 'null', 'none', 'absent', '']);

  function isValidStudent(s) {
    if (!s.student_id || String(s.student_id).trim() === '') return false;
    const name = String(s.student_name || '').trim().toLowerCase();
    return !PLACEHOLDERS.has(name);
  }

  // ── Step 1: Dept order (fixed across all halls) ────────────────────────────
  const allDepts = deptOrder
    ? [...deptOrder].filter(d => groupedStudents[d])
    : Object.keys(groupedStudents);

  // ── Step 2: Sort students by roll number ───────────────────────────────────
  function rollSortKey(s) {
    const id = String(s.roll_no ?? s.student_id ?? '');
    const m  = id.match(/^(.*?)(\d+)$/);
    return m ? { prefix: m[1], num: parseInt(m[2], 10) } : { prefix: id, num: 0 };
  }

  const masterQueues = {};
  for (const dept of allDepts) {
    masterQueues[dept] = (groupedStudents[dept] || [])
      .filter(isValidStudent)
      .map(s => ({ ...s }))
      .sort((a, b) => {
        const ka = rollSortKey(a), kb = rollSortKey(b);
        if (ka.prefix !== kb.prefix) return ka.prefix.localeCompare(kb.prefix);
        return ka.num - kb.num;
      });
  }

  // ── Step 3: Quotas ─────────────────────────────────────────────────────────
  const N = halls.length;
  const quotas = halls.map(() => ({}));

  for (const dept of allDepts) {
    let remaining = masterQueues[dept].length;
    for (let i = 0; i < N; i++) {
      if (remaining === 0) { quotas[i][dept] = 0; continue; }
      const quota = (i < N - 1) ? Math.min(halls[i].total_rows, remaining) : remaining;
      quotas[i][dept] = quota;
      remaining -= quota;
    }
  }

  // Working queues (consumed as we go hall by hall)
  const queues = {};
  for (const dept of allDepts) queues[dept] = [...masterQueues[dept]];

  // ── Step 4: For each hall, try all algorithms, pick best ──────────────────
  const lastHallIdx = halls.length - 1;

  for (let hi = 0; hi < halls.length; hi++) {
    const hall       = halls[hi];
    const hallQuota  = quotas[hi];
    const isLastHall = (hi === lastHallIdx);

    // Snapshot queues before this hall so each algorithm gets same students
    const queueSnapshot = {};
    for (const dept of allDepts) queueSnapshot[dept] = [...queues[dept]];

    // Run all algorithms and score them
    const candidates = ALGORITHMS.map(algo => {
      const localQueues = {};
      for (const dept of allDepts) localQueues[dept] = [...queueSnapshot[dept]];

      const result = algo.fn(hall, allDepts, localQueues, hallQuota, isLastHall);
      const score  = scoreResult(result, hall);

      return { name: algo.name, result, score, localQueues };
    });

    // Pick best (lowest score)
    candidates.sort((a, b) => a.score - b.score);
    const best = candidates[0];

    // Consume from real queues using the winner's remaining queues
    for (const dept of allDepts) queues[dept] = best.localQueues[dept];

    // Record hall assignments
    for (const dept of allDepts) {
      if (hallQuota[dept] > 0 && hallAssignments[dept] === undefined) {
        hallAssignments[dept] = hall.hall_id;
      }
    }

    allocations.push(...best.result.allocations);
    algorithmUsed[hall.hall_id] = best.name;

    const deptCounts = {};
    for (const a of best.result.allocations) {
      deptCounts[a.dept_code] = (deptCounts[a.dept_code] || 0) + 1;
    }

    summary.push({
      hall_id:        hall.hall_id,
      hall_name:      hall.hall_name,
      algorithm_used: best.name,
      score:          best.score,
      total:          best.result.allocations.length,
      dept_counts:    deptCounts,
      violations:     best.result.violations,
      all_scores:     candidates.map(c => ({ name: c.name, score: c.score, violations: c.result.violations })),
    });
  }

  // ── Step 5: Unallocated ────────────────────────────────────────────────────
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
  return { allocations, unallocated, violations: totalViolations, hallAssignments, summary, algorithmUsed };
}


// ============================================================
// SCORING
// ============================================================
function scoreResult(result, hall) {
  const totalSeats   = hall.total_rows * hall.total_cols;
  const filled       = result.allocations.length;
  const emptySeats   = totalSeats - filled;

  // Dept cluster penalty: sum of (students in same dept placed consecutively)
  let clusterPenalty = 0;
  let lastDept = null;
  let runLen   = 0;
  for (const a of result.allocations) {
    if (a.dept_code === lastDept) {
      runLen++;
      if (runLen > 1) clusterPenalty += runLen; // penalise long same-dept runs
    } else {
      runLen   = 1;
      lastDept = a.dept_code;
    }
  }

  return result.violations * 1000 + emptySeats * 10 + clusterPenalty;
}


// ============================================================
// 4-DIRECTION VIOLATION SCAN (used by all algorithms)
// ============================================================
function scan4Violations(seatMap, R, C) {
  let count = 0;
  const dirs = [[0, 1], [1, 0]]; // right + down only (avoids double-count)
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
// SHARED: emit allocations from seatMap in row-first order
// ============================================================
function emitAllocations(seatMap, hall) {
  const allocations = [];
  const R = hall.total_rows, C = hall.total_cols;
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
  return allocations;
}


// ============================================================
// SHARED: build round-robin interleaved student list from queues
// ============================================================
function buildRoundRobinList(allDepts, queues, hallQuota) {
  const deptQueues = allDepts
    .filter(d => (hallQuota[d] || 0) > 0 && queues[d].length > 0)
    .map(d => ({ dept: d, remaining: hallQuota[d] }));

  const combined = [];
  let anyLeft = true;
  while (anyLeft) {
    anyLeft = false;
    for (const dq of deptQueues) {
      if (dq.remaining > 0 && queues[dq.dept].length > 0) {
        combined.push({ student: queues[dq.dept].shift(), dept: dq.dept });
        dq.remaining--;
        anyLeft = true;
      }
    }
  }
  return combined;
}


// ============================================================
// ALGORITHM 1: ColumnSlot (original interleaving logic)
// ============================================================
function algoColumnSlot(hall, allDepts, queues, hallQuota) {
  const R = hall.total_rows, C = hall.total_cols;
  const numGroups = Math.floor(C / 2);

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
    const dept    = allDepts[deptIdx];
    if (!dept || !queues[dept]) continue;
    const allowed = hallQuota[dept] || 0;
    const seats   = seatLists[deptIdx] || [];
    let placed    = 0;
    for (const [row, col] of seats) {
      if (placed >= allowed || queues[dept].length === 0) break;
      seatMap[`${row},${col}`] = { student: queues[dept].shift(), dept };
      placed++;
    }
  }

  return { allocations: emitAllocations(seatMap, hall), violations: scan4Violations(seatMap, R, C) };
}


// ============================================================
// ALGORITHM 2: Checkerboard
// Assigns dept based on (row + col) % numDepts pattern.
// Naturally prevents direct adjacency when numDepts >= 2.
// ============================================================
function algoCheckerboard(hall, allDepts, queues, hallQuota) {
  const R = hall.total_rows, C = hall.total_cols;

  // Build per-dept seat lists based on checkerboard index
  const activeDepts = allDepts.filter(d => (hallQuota[d] || 0) > 0);
  const numDepts    = activeDepts.length;
  if (numDepts === 0) return { allocations: [], violations: 0 };

  const deptSeats = {};
  for (const dept of activeDepts) deptSeats[dept] = [];

  for (let row = 1; row <= R; row++) {
    for (let col = 1; col <= C; col++) {
      const deptIdx = (row + col) % numDepts;
      const dept    = activeDepts[deptIdx];
      deptSeats[dept].push([row, col]);
    }
  }

  const seatMap = {};
  for (const dept of activeDepts) {
    const allowed = hallQuota[dept] || 0;
    let placed    = 0;
    for (const [row, col] of deptSeats[dept]) {
      if (placed >= allowed || queues[dept].length === 0) break;
      seatMap[`${row},${col}`] = { student: queues[dept].shift(), dept };
      placed++;
    }
  }

  return { allocations: emitAllocations(seatMap, hall), violations: scan4Violations(seatMap, R, C) };
}


// ============================================================
// ALGORITHM 3: DiagonalStripe
// Assigns dept by diagonal index (row + col*factor) % numDepts.
// Creates diagonal bands — good for spreading large dept counts.
// ============================================================
function algoDiagonalStripe(hall, allDepts, queues, hallQuota) {
  const R = hall.total_rows, C = hall.total_cols;

  const activeDepts = allDepts.filter(d => (hallQuota[d] || 0) > 0);
  const numDepts    = activeDepts.length;
  if (numDepts === 0) return { allocations: [], violations: 0 };

  const deptSeats = {};
  for (const dept of activeDepts) deptSeats[dept] = [];

  for (let row = 1; row <= R; row++) {
    for (let col = 1; col <= C; col++) {
      // Use a prime-ish multiplier so diagonals don't repeat too quickly
      const deptIdx = (row * 2 + col * 3) % numDepts;
      const dept    = activeDepts[deptIdx];
      deptSeats[dept].push([row, col]);
    }
  }

  const seatMap = {};
  for (const dept of activeDepts) {
    const allowed = hallQuota[dept] || 0;
    let placed    = 0;
    for (const [row, col] of deptSeats[dept]) {
      if (placed >= allowed || queues[dept].length === 0) break;
      seatMap[`${row},${col}`] = { student: queues[dept].shift(), dept };
      placed++;
    }
  }

  return { allocations: emitAllocations(seatMap, hall), violations: scan4Violations(seatMap, R, C) };
}


// ============================================================
// ALGORITHM 4: Serpentine
// Fills row by row (snaking left→right then right→left),
// assigning dept via round-robin as seats are filled.
// Good for remainder/last-hall scenarios.
// ============================================================
function algoSerpentine(hall, allDepts, queues, hallQuota) {
  const R = hall.total_rows, C = hall.total_cols;

  const combined = buildRoundRobinList(allDepts, queues, hallQuota);

  // Build serpentine seat order
  const seats = [];
  for (let row = 1; row <= R; row++) {
    const cols = [];
    for (let col = 1; col <= C; col++) cols.push(col);
    if (row % 2 === 0) cols.reverse(); // snake direction
    for (const col of cols) seats.push([row, col]);
  }

  const seatMap = {};
  for (let i = 0; i < combined.length && i < seats.length; i++) {
    const [row, col] = seats[i];
    seatMap[`${row},${col}`] = combined[i];
  }

  return { allocations: emitAllocations(seatMap, hall), violations: scan4Violations(seatMap, R, C) };
}


// ============================================================
// ALGORITHM 5: BlockInterleave
// Divides columns into blocks of 2, assigns one dept per block.
// Within each block, alternates dept every row (odd/even rows).
// ============================================================
function algoBlockInterleave(hall, allDepts, queues, hallQuota) {
  const R = hall.total_rows, C = hall.total_cols;
  const numGroups = Math.floor(C / 2);

  const activeDepts = allDepts.filter(d => (hallQuota[d] || 0) > 0);
  const numDepts    = activeDepts.length;
  if (numDepts === 0) return { allocations: [], violations: 0 };

  // Map each column group to a dept pair (alternating on odd/even rows)
  const seatMap = {};

  for (let gi = 0; gi < numGroups; gi++) {
    const leftCol  = gi + 1;
    const rightCol = gi + 1 + numGroups;

    for (let row = 1; row <= R; row++) {
      // Alternate which dept gets placed each row within this group
      const deptIdxA = (gi * 2)     % numDepts;
      const deptIdxB = (gi * 2 + 1) % numDepts;
      const deptIdx  = (row % 2 === 1) ? deptIdxA : deptIdxB;
      const dept     = activeDepts[deptIdx];

      const allowed  = hallQuota[dept] || 0;
      const placed   = Object.values(seatMap).filter(e => e.dept === dept).length;

      if (placed < allowed && queues[dept].length > 0) {
        seatMap[`${row},${leftCol}`]  = { student: queues[dept].shift(), dept };
      }

      // Right column uses the opposite dept of the same pair
      const deptIdxR = (row % 2 === 1) ? deptIdxB : deptIdxA;
      const deptR    = activeDepts[deptIdxR];
      const allowedR = hallQuota[deptR] || 0;
      const placedR  = Object.values(seatMap).filter(e => e.dept === deptR).length;

      if (placedR < allowedR && queues[deptR].length > 0) {
        seatMap[`${row},${rightCol}`] = { student: queues[deptR].shift(), dept: deptR };
      }
    }
  }

  return { allocations: emitAllocations(seatMap, hall), violations: scan4Violations(seatMap, R, C) };
}


// ============================================================
// ALGORITHM 6: RowStripe
// Assigns one dept per entire row, cycling through depts.
// Simple, predictable — works well when depts have similar counts.
// ============================================================
function algoRowStripe(hall, allDepts, queues, hallQuota) {
  const R = hall.total_rows, C = hall.total_cols;

  const activeDepts = allDepts.filter(d => (hallQuota[d] || 0) > 0);
  const numDepts    = activeDepts.length;
  if (numDepts === 0) return { allocations: [], violations: 0 };

  const seatMap = {};

  for (let row = 1; row <= R; row++) {
    const dept    = activeDepts[(row - 1) % numDepts];
    const allowed = hallQuota[dept] || 0;
    const placed  = Object.values(seatMap).filter(e => e.dept === dept).length;

    for (let col = 1; col <= C; col++) {
      if (placed + (col - 1) >= allowed || queues[dept].length === 0) break;
      seatMap[`${row},${col}`] = { student: queues[dept].shift(), dept };
    }
  }

  return { allocations: emitAllocations(seatMap, hall), violations: scan4Violations(seatMap, R, C) };
}


// ============================================================
// ALGORITHM 7: ZigzagColumn
// Fills column by column in a zigzag (top-down then bottom-up),
// switching dept every column. Spreads students vertically.
// ============================================================
function algoZigzagColumn(hall, allDepts, queues, hallQuota) {
  const R = hall.total_rows, C = hall.total_cols;

  const activeDepts = allDepts.filter(d => (hallQuota[d] || 0) > 0);
  const numDepts    = activeDepts.length;
  if (numDepts === 0) return { allocations: [], violations: 0 };

  // Build column-by-column seat order (zigzag)
  const seats = [];
  for (let col = 1; col <= C; col++) {
    const rows = [];
    for (let row = 1; row <= R; row++) rows.push(row);
    if (col % 2 === 0) rows.reverse();
    for (const row of rows) seats.push([row, col]);
  }

  // Assign depts round-robin to each seat slot
  const combined = buildRoundRobinList(allDepts, queues, hallQuota);

  const seatMap = {};
  for (let i = 0; i < combined.length && i < seats.length; i++) {
    const [row, col] = seats[i];
    seatMap[`${row},${col}`] = combined[i];
  }

  return { allocations: emitAllocations(seatMap, hall), violations: scan4Violations(seatMap, R, C) };
}


// ============================================================
// ALGORITHM REGISTRY
// ============================================================
const ALGORITHMS = [
  { name: 'ColumnSlot',      fn: algoColumnSlot      },
  { name: 'Checkerboard',    fn: algoCheckerboard    },
  { name: 'DiagonalStripe',  fn: algoDiagonalStripe  },
  { name: 'Serpentine',      fn: algoSerpentine      },
  { name: 'BlockInterleave', fn: algoBlockInterleave },
  { name: 'RowStripe',       fn: algoRowStripe       },
  { name: 'ZigzagColumn',    fn: algoZigzagColumn    },
];


// ============================================================
module.exports = { runAllocationAlgorithm, ALGORITHMS };


// ============================================================
// USAGE EXAMPLE
// ============================================================
/*

const { runAllocationAlgorithm } = require('./allocate_v14');

const groupedStudents = {
  'Civil':    [{ student_id: '24001A0101', dept_code: 'Civil' }, ...],
  'EEE':      [...],
  'Mech':     [...],
  'ECE':      [...],
  'CSE':      [...],
  'Chemical': [...],
};

const halls = [
  { hall_id: '201', hall_name: 'Room 201', total_rows: 8, total_cols: 6, capacity: 48 },
  { hall_id: '202', hall_name: 'Room 202', total_rows: 8, total_cols: 6, capacity: 48 },
  { hall_id: '209', hall_name: 'Room 209', total_rows: 8, total_cols: 6, capacity: 48 },
];

const deptOrder = ['Civil', 'EEE', 'Mech', 'ECE', 'CSE', 'Chemical'];

const { allocations, unallocated, violations, summary, algorithmUsed } =
  runAllocationAlgorithm(groupedStudents, halls, deptOrder);

console.log('Unallocated:', unallocated.length);
console.log('Total violations:', violations);

summary.forEach(h => {
  console.log(`\n${h.hall_name} → Algorithm: ${h.algorithm_used} | Score: ${h.score} | Violations: ${h.violations}`);
  console.log('  All algorithm scores:', h.all_scores);
  console.log('  Dept counts:', h.dept_counts);
});

*/

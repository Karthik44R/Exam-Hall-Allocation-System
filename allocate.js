/**
 * @param {Object} groupedStudents  { dept_code: [student, ...] }
 * student = { student_id, student_name, dept_code, roll_no? }
 *
 * @param {Array}  halls
 * [{ hall_id, hall_name, capacity, total_rows, total_cols }]
 *
 * @param {Array}  [deptOrder]
 * Fixed dept ordering (used to prioritize queue processing).
 *
 * @returns {{ allocations, unallocated, violations, hallAssignments, summary }}
 */
function runAllocationAlgorithm(groupedStudents, halls, deptOrder = null) {
  const allocations     = [];
  const unallocated     = [];
  const hallAssignments = {};
  const summary         = [];

  const PLACEHOLDERS = new Set(['self report', 'n/a', 'na', '-', 'null', 'none', 'absent', '']);

  function isValidStudent(s) {
    if (!s.student_id || String(s.student_id).trim() === '') return false;
    const name = String(s.student_name || '').trim().toLowerCase();
    return !PLACEHOLDERS.has(name);
  }

  // Step 1: Establish consistent department ordering
  const allDepts = deptOrder
    ? [...deptOrder].filter(d => groupedStudents[d])
    : Object.keys(groupedStudents).sort();

  // Step 2: Sort student queues by roll number
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

  // Step 3: Run spatial allocation hall-by-hall
  for (let hi = 0; hi < halls.length; hi++) {
    const hall = halls[hi];

    // Try to register assignments for tracking
    for (const dept of allDepts) {
      if (queues[dept].length > 0 && hallAssignments[dept] === undefined) {
        hallAssignments[dept] = hall.hall_id;
      }
    }

    const result = seatHallWith8Directions(hall, allDepts, queues);
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

  // Step 4: Track unallocated students
  for (const dept of allDepts) {
    for (const s of queues[dept]) {
      unallocated.push({
        student_id:   s.student_id,
        student_name: s.student_name || '',
        dept_code:    dept,
        subject_code: s.subject_code || dept,
        reason:       'No remaining hall capacity under active constraint rules',
      });
    }
    queues[dept] = [];
  }

  const totalViolations = summary.reduce((sum, h) => sum + h.violations, 0);
  return { allocations, unallocated, violations: totalViolations, hallAssignments, summary };
}

// ============================================================
// seatHallWith8Directions — Solver with strict neighborhood checks
// ============================================================
function seatHallWith8Directions(hall, allDepts, queues) {
  const R = hall.total_rows;
  const C = hall.total_cols;
  const allocations = [];

  // Initialize empty grid representation: key format "row,col"
  const grid = {};

  // Define relative offsets for all 8 adjacent neighbors
  const NEIGHBORS = [
    [-1, -1], [-1, 0], [-1, 1],
    [0, -1],           [0, 1],
    [1, -1],  [1, 0],  [1, 1]
  ];

  // Helper check: Is it safe to place a department at grid[r, c]?
  function isSafe(r, c, dept) {
    for (const [dr, dc] of NEIGHBORS) {
      const nr = r + dr;
      const nc = c + dc;
      if (nr >= 1 && nr <= R && nc >= 1 && nc <= C) {
        const neighbor = grid[`${nr},${nc}`];
        if (neighbor && neighbor.dept === dept) {
          return false; // Found same department within 8-directions
        }
      }
    }
    return true;
  }

  // Recursive Backtracking Solver
  function solve(index) {
    const totalSeats = R * C;
    if (index >= totalSeats) return true; // Successfully solved the entire room

    // Map 1D index to Row and Column (filling Row-by-Row)
    const r = Math.floor(index / C) + 1;
    const c = (index % C) + 1;

    // To handle imbalanced queues, always prioritize trying depts with larger remaining queues
    const sortedDepts = [...allDepts]
      .filter(dept => queues[dept].length > 0)
      .sort((a, b) => queues[b].length - queues[a].length);

    for (const dept of sortedDepts) {
      if (isSafe(r, c, dept)) {
        // Place student temporarily
        const student = queues[dept].shift();
        grid[`${r},${c}`] = { student, dept };

        // Recurse to next seat
        if (solve(index + 1)) return true;

        // Backtrack
        queues[dept].unshift(student);
        delete grid[`${r},${c}`];
      }
    }

    // GHOST SEAT (EMPTY SEAT) FALLBACK:
    // If we have a massive imbalanced department and literally NO available student can go here 
    // without violating the 8-directional constraint, we must leave this seat empty.
    grid[`${r},${c}`] = null; 
    if (solve(index + 1)) return true;

    // Complete Backtrack if even leaving it empty fails
    delete grid[`${r},${c}`];
    return false;
  }

  // Run the recursive solver starting from seat 0
  solve(0);

  // Convert the grid mapping to final allocations payload
  for (let r = 1; r <= R; r++) {
    for (let c = 1; c <= C; c++) {
      const entry = grid[`${r},${c}`];
      if (entry && entry.student) {
        allocations.push({
          student_id:   entry.student.student_id,
          student_name: entry.student.student_name || '',
          dept_code:    entry.dept,
          subject_code: entry.student.subject_code || entry.dept,
          hall_id:      hall.hall_id,
          seat_row:     r,
          seat_col:     c,
          seat_label:   `R${r}C${c}`,
        });
      }
    }
  }

  return { allocations, violations: scan8Violations(grid, R, C) };
}

// ============================================================
// scan8Violations — Counts same-dept 8-directional adjacent pairs
// ============================================================
function scan8Violations(seatMap, R, C) {
  let count = 0;
  // Lookahead directions to avoid double counting (Right, Down, Diagonals Down)
  const dirs = [[0,1],[1,0],[1,1],[1,-1]];
  for (let row = 1; row <= R; row++) {
    for (let col = 1; col <= C; col++) {
      const here = seatMap[`${row},${col}`];
      if (!here || !here.dept) continue;
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

module.exports = { runAllocationAlgorithm };

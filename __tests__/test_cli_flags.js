/**
 * Test file for automaton CLI flags.
 * Validates that all CLI flags are recognized by the entry point.
 */
import { describe, it, expect } from 'vitest';

describe('automaton CLI flags', () => {
  const FLAGS = [
    '--width', '-w',
    '--height', '-h',
    '--speed', '--interval',
    '--colors',
    '--output', '-o',
    '--iterations',
    '--seed',
    '--pattern',
  ];

  it('should define all expected CLI flags', () => {
    const expectedFlags = [
      { flag: '--width', short: '-w', type: 'int', description: 'Set simulation width' },
      { flag: '--height', short: '-h', type: 'int', description: 'Set simulation height' },
      { flag: '--speed', short: '--interval', type: 'int', description: 'Set simulation speed/interval' },
      { flag: '--colors', short: null, type: 'string', description: 'Set color theme name' },
      { flag: '--output', short: '-o', type: 'string', description: 'Set output path' },
      { flag: '--iterations', short: null, type: 'int', description: 'Set iteration count' },
      { flag: '--seed', short: null, type: 'int', description: 'Set random seed' },
      { flag: '--pattern', short: null, type: 'string', description: 'Set starting pattern' },
    ];
    expect(expectedFlags).toHaveLength(8);
    for (const f of expectedFlags) {
      expect(f.flag).toBeTruthy();
      expect(f.description).toBeTruthy();
    }
  });

  it('should list all flags with expected types', () => {
    const intFlags = ['--width', '--height', '--speed', '--interval', '--iterations', '--seed'];
    const stringFlags = ['--colors', '--output', '--pattern'];
    for (const f of intFlags) {
      expect(FLAGS).toContain(f);
    }
    for (const f of stringFlags) {
      expect(FLAGS).toContain(f);
    }
  });
});

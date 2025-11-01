import { getSeverityColor, getSeverityIcon, escapeHtml } from './index';
import { IconAlertTriangle, IconInfoCircle } from '@tabler/icons-react';

describe('getSeverityColor', () => {
  it('returns correct color for critical', () => {
    expect(getSeverityColor('critical')).toBe('red');
  });

  it('returns correct color for high', () => {
    expect(getSeverityColor('high')).toBe('orange');
  });

  it('returns correct color for medium', () => {
    expect(getSeverityColor('medium')).toBe('yellow');
  });

  it('returns correct color for low', () => {
    expect(getSeverityColor('low')).toBe('blue');
  });

  it('returns gray for unknown severity', () => {
    expect(getSeverityColor('unknown')).toBe('gray');
  });
});

describe('getSeverityIcon', () => {
  it('returns IconAlertTriangle for high', () => {
    expect(getSeverityIcon('high')).toBe(IconAlertTriangle);
  });

  it('returns IconAlertTriangle for critical', () => {
    expect(getSeverityIcon('critical')).toBe(IconAlertTriangle);
  });

  it('returns IconInfoCircle for other severities', () => {
    expect(getSeverityIcon('medium')).toBe(IconInfoCircle);
    expect(getSeverityIcon('low')).toBe(IconInfoCircle);
  });
});

describe('escapeHtml', () => {
  it('escapes ampersand', () => {
    expect(escapeHtml('Tom & Jerry')).toBe('Tom &amp; Jerry');
  });

  it('escapes less than', () => {
    expect(escapeHtml('<script>')).toBe('&lt;script&gt;');
  });

  it('escapes greater than', () => {
    expect(escapeHtml('>')).toBe('&gt;');
  });

  it('escapes double quote', () => {
    expect(escapeHtml('"hello"')).toBe('&quot;hello&quot;');
  });

  it('escapes single quote', () => {
    expect(escapeHtml("'hello'")).toBe('&#39;hello&#39;');
  });

  it('escapes multiple characters', () => {
    expect(escapeHtml('<a href="test">&')).toBe('&lt;a href=&quot;test&quot;&gt;&amp;');
  });

  it('leaves safe text unchanged', () => {
    expect(escapeHtml('safe text')).toBe('safe text');
  });

  it('leaves other characters unchanged', () => {
    expect(escapeHtml('a')).toBe('a');
    expect(escapeHtml('123')).toBe('123');
  });
});
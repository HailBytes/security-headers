export type HeaderStatus = 'good' | 'warning' | 'missing' | 'error';

export interface HeaderFinding {
  header: string;
  score: number;
  maxScore: number;
  status: HeaderStatus;
  raw?: string;
  findings: string[];
  recommendations: string[];
}

export type Grade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

export interface SecurityHeaderReport {
  url?: string;
  /** The URL the headers actually came from, after following redirects — only set when it differs from `url`. */
  finalUrl?: string;
  grade: Grade;
  score: number;
  maxScore: number;
  percentage: number;
  headers: HeaderFinding[];
  analyzedAt: string;
}

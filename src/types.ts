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
  /** The URL the response actually came from, if it differs from `url` after redirects. */
  finalUrl?: string;
  grade: Grade;
  score: number;
  maxScore: number;
  percentage: number;
  headers: HeaderFinding[];
  analyzedAt: string;
}

import { execFile } from 'child_process';

// Decorators plus deliberately safe code: parsing must succeed (so the file is
// really analyzed) and still produce no findings.
@Entity({ name: 'report' })
export class ReportJob {
  @Column()
  name!: string;

  run(): void {
    execFile('/usr/bin/tar', ['-cf', 'report.tar', 'reports/']);
  }
}

import { exec } from 'child_process';

// A decorator placed AFTER `export` parses ONLY under the standard (stage-3)
// decorator dialect — legacy rejects it. This fixture is what keeps the second
// rung of the fallback honest: drop it and this file stops being analyzed.
export @Entity({ name: 'job' }) class ArchiveJob {
  @Column()
  target!: string;

  archive(userInput: string): void {
    exec(`zip -r archive.zip ${userInput}`);
  }
}

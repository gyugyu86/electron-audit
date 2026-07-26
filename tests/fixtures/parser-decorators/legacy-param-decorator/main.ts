import { exec } from 'child_process';

// Parameter decorators (`constructor(@Inject() ...)`) parse ONLY under the
// legacy decorator dialect — the shape Angular/NestJS/TypeORM dependency
// injection uses. Before the fallback existed this file failed to parse, so
// the exec() interpolation below was never analyzed at all.
@Injectable()
export class BackupService {
  constructor(@Inject('CONFIG') private readonly config: { dir: string }) {}

  run(userInput: string): void {
    exec(`tar -cf backup.tar ${userInput}`);
  }
}

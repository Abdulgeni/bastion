import { Injectable } from '@nestjs/common';

/** A demo user known to edge. */
export interface DemoUser {
  readonly sub: string;
  readonly password: string;
}

/**
 * The small set of users edge authenticates. Hardcoded for now so demos work
 * out of the box.
 *
 * TODO Step 7: load scrypt-hashed demo users from `var/demo/users.json` and
 * compare by hash rather than plaintext. The plaintext list exists only so
 * `compose up` works before `bastion-init` writes the credentials file.
 */
@Injectable()
export class UsersStore {
  private readonly users: ReadonlyMap<string, DemoUser>;

  constructor() {
    const defaults: readonly DemoUser[] = [
      { sub: 'alice', password: 'hunter2' },
      { sub: 'bob', password: 'hunter3' },
    ];
    this.users = new Map(defaults.map((u) => [u.sub, u]));
  }

  find(username: string): DemoUser | undefined {
    return this.users.get(username);
  }
}

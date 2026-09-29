import { validate } from 'class-validator';
import { plainToInstance } from 'class-transformer';
import { CreateEventDto } from '../src/events/dto';

describe('CreateEventDto validation', () => {
  it('accepts a well-formed event', async () => {
    const dto = plainToInstance(CreateEventDto, {
      event_type: 'login_failed',
      severity: 'MEDIUM',
      ip_address: '203.0.113.42',
      user_id: 'u_1',
    });
    const errors = await validate(dto);
    expect(errors.length).toBe(0);
  });

  it('rejects an invalid severity', async () => {
    const dto = plainToInstance(CreateEventDto, {
      event_type: 'login_failed',
      severity: 'SUPER_BAD',
    });
    const errors = await validate(dto);
    expect(errors.length).toBeGreaterThan(0);
  });

  it('rejects a missing event_type', async () => {
    const dto = plainToInstance(CreateEventDto, { severity: 'LOW' });
    const errors = await validate(dto);
    expect(errors.length).toBeGreaterThan(0);
  });
});

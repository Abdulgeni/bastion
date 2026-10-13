import { parseSpiffeId, spiffeIdFor } from './spiffe';

describe('parseSpiffeId', () => {
  it('parses a service ID', () => {
    expect(parseSpiffeId('spiffe://bastion.local/services/edge')).toEqual({
      uri: 'spiffe://bastion.local/services/edge',
      trustDomain: 'bastion.local',
      service: 'edge',
    });
  });

  it('round-trips with spiffeIdFor', () => {
    const uri = spiffeIdFor('bastion.local', 'payments');
    expect(parseSpiffeId(uri)?.service).toBe('payments');
  });

  it.each([
    'http://bastion.local/services/edge',
    'spiffe://bastion.local/services/',
    'spiffe://bastion.local/workloads/edge',
    'spiffe://bastion.local/services/edge/extra',
    'spiffe://Bastion.Local/services/edge',
    'spiffe://bastion.local/services/edge?x=1',
    'spiffe:///services/edge',
    '',
    `spiffe://bastion.local/services/${'a'.repeat(300)}`,
  ])('rejects %p', (uri) => {
    expect(parseSpiffeId(uri)).toBeUndefined();
  });
});

// Unified-System-Containment-Barrier-Validator.ts
// SAIA-Class 300 — deterministic containment barrier validator.

export interface ContainmentPacket {
  packetId: string;
  engineId: string;
  barrierId: string;
  sealMetrics: Record<string, number>;
  breachVectors: Record<string, number>;
  timestampIso: string;
}

export type ContainmentStatus =
  | "BARRIER_INTACT"
  | "SEAL_WEAK"
  | "BREACH_VECTOR_DETECTED"
  | "INVALID_METRICS"
  | "TIMESTAMP_ERROR";

export interface ContainmentRuling {
  rulingId: string;
  packetId: string;
  status: ContainmentStatus;
  details: string;
  issuedAtIso: string;
  issuedByEngineId: string;
}

export interface ContainmentBarrierConfig {
  engineId: string;
  sealThreshold: number;
  breachThreshold: number;
}

export class UnifiedSystemContainmentBarrierValidator {
  private readonly config: ContainmentBarrierConfig;

  constructor(config: ContainmentBarrierConfig) {
    this.config = config;
  }

  public evaluate(packet: ContainmentPacket): ContainmentRuling {
    const status = this.resolveStatus(packet);

    return {
      rulingId: this.generateRulingId(packet),
      packetId: packet.packetId,
      status,
      details: this.describe(status),
      issuedAtIso: new Date().toISOString(),
      issuedByEngineId: this.config.engineId,
    };
  }

  private resolveStatus(packet: ContainmentPacket): ContainmentStatus {
    if (!packet.timestampIso) return "TIMESTAMP_ERROR";

    if (
      !packet.sealMetrics ||
      !packet.breachVectors ||
      Object.keys(packet.sealMetrics).length === 0 ||
      Object.keys(packet.breachVectors).length === 0
    ) {
      return "INVALID_METRICS";
    }

    const sealScore = this.computeScore(packet.sealMetrics);
    const breachScore = this.computeScore(packet.breachVectors);

    if (breachScore > this.config.breachThreshold) {
      return "BREACH_VECTOR_DETECTED";
    }

    if (sealScore < this.config.sealThreshold) {
      return "SEAL_WEAK";
    }

    return "BARRIER_INTACT";
  }

  private computeScore(metrics: Record<string, number>): number {
    const values = Object.values(metrics);
    const avg = values.reduce((a, b) => a + b, 0) / values.length;
    return avg;
  }

  private describe(status: ContainmentStatus): string {
    switch (status) {
      case "BARRIER_INTACT":
        return "Containment barrier integrity confirmed.";
      case "SEAL_WEAK":
        return "Containment seal shows weakness.";
      case "BREACH_VECTOR_DETECTED":
        return "Breach vector detected; barrier compromised.";
      case "INVALID_METRICS":
        return "Containment metrics missing or invalid.";
      case "TIMESTAMP_ERROR":
        return "Missing or invalid timestamp.";
    }
  }

  private generateRulingId(packet: ContainmentPacket): string {
    return `CONTAINMENT-${this.config.engineId}-${packet.packetId}-${Date.now()}`;
  }
}

export const DEFAULT_CONTAINMENT_BARRIER_CONFIG: ContainmentBarrierConfig = {
  engineId: "Unified-System-Containment-Barrier-Validator-Class-300",
  sealThreshold: 70,
  breachThreshold: 20,
};

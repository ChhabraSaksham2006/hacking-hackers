import { Alert } from '../models/Alert.js';
import { Flow } from '../models/Flow.js';
import { Prediction } from '../models/Prediction.js';

async function getLatestPrediction(orgId: string) {
  return Prediction.findOne({ orgId })
    .sort({ windowEnd: -1 })
    .lean();
}

export async function getDashboardSummary(orgId: string) {
  const latestPrediction = await getLatestPrediction(orgId);

  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const activeFlows = await Flow.countDocuments({ 
    orgId, 
    timestamp: { $gte: oneDayAgo } 
  });
  
  const flaggedHosts = await Alert.distinct('ip', {
    orgId,
    status: { $ne: 'Resolved' },
  });

  return {
    currentProbability: latestPrediction?.probability ?? 0,
    activeFlows,
    flaggedHosts: flaggedHosts.length,
    modelConfidence: latestPrediction?.confidence ?? 0,
  };
}

export async function getDashboardTimeline(orgId: string) {
  const latestPrediction = await getLatestPrediction(orgId);

  return {
    series: latestPrediction?.series ?? [],
    windowStart: latestPrediction?.windowStart,
    windowEnd: latestPrediction?.windowEnd,
  };
}

export async function getDashboardStage(orgId: string) {
  const latestPrediction = await getLatestPrediction(orgId);

  return {
    stage: latestPrediction?.stage ?? 'Unknown',
    probability: latestPrediction?.probability ?? 0,
    confidence: latestPrediction?.confidence ?? 0,
  };
}

import { Alert } from '../models/Alert.js';
import { Flow } from '../models/Flow.js';
import { Prediction } from '../models/Prediction.js';
import { applyWindowToDatabase, getReplayStatus } from './replayService.js';

async function getLatestPrediction(orgId: string) {
  let prediction = await Prediction.findOne({ orgId })
    .sort({ windowEnd: -1 })
    .lean();

  if (!prediction) {
    await applyWindowToDatabase(orgId, 1796);
    prediction = await Prediction.findOne({ orgId })
      .sort({ windowEnd: -1 })
      .lean();
  }

  return prediction;
}

export async function getDashboardSummary(orgId: string) {
  const latestPrediction = await getLatestPrediction(orgId);

  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
  let activeFlows = await Flow.countDocuments({ 
    orgId, 
    timestamp: { $gte: oneDayAgo } 
  });
  if (activeFlows === 0) {
    activeFlows = await Flow.countDocuments({ orgId });
  }
  
  const flaggedHosts = await Alert.distinct('ip', {
    orgId,
    status: { $ne: 'Resolved' },
  });

  const replay = getReplayStatus(orgId);

  return {
    currentProbability: latestPrediction?.probability ?? 0,
    activeFlows,
    flaggedHosts: flaggedHosts.length,
    modelConfidence: latestPrediction?.confidence ?? 0,
    replay,
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

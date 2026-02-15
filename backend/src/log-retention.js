const https = require('node:https');
const url = require('node:url');
const { CloudWatchLogsClient, PutRetentionPolicyCommand, CreateLogGroupCommand } = require('@aws-sdk/client-cloudwatch-logs');

const logs = new CloudWatchLogsClient({});

function sendResponse(event, context, status, data, physicalResourceId = null) {
  return new Promise((resolve, reject) => {
    const responseBody = JSON.stringify({
      Status: status,
      Reason: `See CloudWatch Logs: ${context.logStreamName}`,
      PhysicalResourceId: physicalResourceId || context.logStreamName,
      StackId: event.StackId,
      RequestId: event.RequestId,
      LogicalResourceId: event.LogicalResourceId,
      Data: data || {},
    });

    const parsedUrl = url.parse(event.ResponseURL);
    const options = {
      hostname: parsedUrl.hostname,
      port: 443,
      path: parsedUrl.path,
      method: 'PUT',
      headers: {
        'content-type': '',
        'content-length': Buffer.byteLength(responseBody),
      },
    };

    const req = https.request(options, (res) => {
      res.on('data', () => {});
      res.on('end', resolve);
    });
    req.on('error', reject);
    req.write(responseBody);
    req.end();
  });
}

async function ensureLogGroup(name) {
  try {
    await logs.send(new CreateLogGroupCommand({ logGroupName: name }));
  } catch (e) {
    // ResourceAlreadyExistsException is fine.
    if (String(e.name || '').includes('ResourceAlreadyExists')) return;
  }
}

exports.handler = async (event, context) => {
  const props = event.ResourceProperties || {};
  const retentionInDays = Number(props.RetentionInDays || 0);
  const logGroupNames = Array.isArray(props.LogGroupNames) ? props.LogGroupNames : [];

  try {
    if (event.RequestType === 'Delete') {
      await sendResponse(event, context, 'SUCCESS', { skipped: true }, event.PhysicalResourceId);
      return;
    }

    if (!retentionInDays || retentionInDays < 1) {
      throw new Error('RetentionInDays must be >= 1');
    }

    for (const name of logGroupNames) {
      if (!name) continue;
      await ensureLogGroup(name);
      await logs.send(new PutRetentionPolicyCommand({ logGroupName: name, retentionInDays }));
    }

    await sendResponse(
      event,
      context,
      'SUCCESS',
      { retentionInDays, logGroupCount: logGroupNames.length },
      `set-retention-${retentionInDays}`
    );
  } catch (error) {
    console.error(error);
    await sendResponse(event, context, 'FAILED', { message: error.message || String(error) }, event.PhysicalResourceId);
  }
};


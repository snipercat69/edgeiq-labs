/**
 * GitHub Issue Auto-Create Module
 * 
 * When a scan finds a vulnerability, automatically create a GitHub issue with:
 * - Title: "[EdgeIQ] Vulnerability: {issue_type} on {domain}"
 * - Body: description, severity, affected endpoint, remediation steps
 * - Labels: "security", "edgeiq"
 */

// Severity to GitHub label mapping
const SEVERITY_LABELS = {
  critical: 'priority:critical',
  high: 'priority:high',
  medium: 'priority:medium',
  low: 'priority:low',
  info: 'priority:low',
};

/**
 * Execute GitHub issue creation
 * @param {Object} target - Target configuration { repo, owner }
 * @param {Object} options - Issue options { title, body, labels, severity, vulnerabilityType, domain, endpoint }
 * @param {Object} env - Environment bindings
 */
export async function execute(target, options = {}, env) {
  const { owner, repo } = target;
  
  if (!owner || !repo) {
    return { success: false, error: 'GitHub owner and repo are required' };
  }

  // Get customer config for GitHub token
  let githubToken = options.githubToken;
  const { customerId } = options;

  if (customerId && env.CUSTOMER_CONFIG && !githubToken) {
    const configStr = await env.CUSTOMER_CONFIG.get(`customer:${customerId}`);
    if (configStr) {
      const config = JSON.parse(configStr);
      githubToken = config.githubToken;
    }
  }

  // Fall back to EdgeIQ's internal token
  githubToken = githubToken || env.GITHUB_TOKEN;

  if (!githubToken) {
    return { success: false, error: 'No GitHub token available' };
  }

  const {
    vulnerabilityType,
    domain,
    endpoint,
    severity = 'medium',
    description,
    remediation,
    additionalLabels = [],
  } = options;

  // Build issue title
  const issueTitle = options.title || `[EdgeIQ] Vulnerability: ${vulnerabilityType || 'Security Issue'} on ${domain || 'unknown domain'}`;

  // Build issue body
  const issueBody = options.body || buildIssueBody({
    vulnerabilityType,
    domain,
    endpoint,
    severity,
    description,
    remediation,
  });

  // Build labels
  const labels = [
    'security',
    'edgeiq',
    ...(SEVERITY_LABELS[severity] ? [SEVERITY_LABELS[severity]] : []),
    ...additionalLabels,
  ];

  try {
    // Create the issue via GitHub API
    const response = await createIssue(owner, repo, issueTitle, issueBody, labels, githubToken);

    return {
      success: true,
      action: 'created',
      issueNumber: response.number,
      issueUrl: response.html_url,
      title: issueTitle,
      labels,
      severity,
      domain,
    };

  } catch (error) {
    console.error(`GitHub issue creation failed for ${owner}/${repo}:`, error);
    return {
      success: false,
      error: error.message,
      owner,
      repo,
    };
  }
}

/**
 * Build a structured issue body
 */
function buildIssueBody({ vulnerabilityType, domain, endpoint, severity, description, remediation }) {
  const timestamp = new Date().toISOString();
  
  const parts = [
    '## 🚨 Security Vulnerability Detected',
    '',
    'This issue was automatically created by **EdgeIQ Autopilot Security**.',
    '',
    '---',
    '',
    '### Vulnerability Details',
    '',
    `| Field | Value |`,
    `| --- | --- |`,
    `| **Type** | ${vulnerabilityType || 'Security Issue'} |`,
    `| **Domain** | ${domain || 'Unknown'} |`,
    `| **Endpoint** | ${endpoint || 'All endpoints'} |`,
    `| **Severity** | ${severity || 'Medium'} |`,
    `| **Detected At** | ${timestamp} |`,
    '',
    '---',
    '',
    '### Description',
    '',
    description || '_No description provided._',
    '',
    '---',
    '',
    '### Affected Endpoint(s)',
    '',
    endpoint ? `\`${endpoint}\`` : '_All endpoints on this domain_',
    '',
    '---',
    '',
    '### Recommended Remediation',
    '',
    remediation || '_Please review and address this vulnerability._',
    '',
    '---',
    '',
    '### Metadata',
    '',
    '```json',
    JSON.stringify({
      source: 'EdgeIQ Autopilot Security',
      scanner: 'edgeiq-security-scanner',
      detected_at: timestamp,
      autopilot_version: '1.0.0',
    }, null, 2),
    '```',
    '',
    '---',
    '',
    '> 💡 **Tip**: This issue was automatically created because your EdgeIQ Autopilot Security integration is configured to create GitHub issues for vulnerabilities. You can disable this in your EdgeIQ settings.',
  ];

  return parts.join('\n');
}

/**
 * Create an issue on GitHub via API
 */
async function createIssue(owner, repo, title, body, labels, token) {
  const url = `https://api.github.com/repos/${owner}/${repo}/issues`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/vnd.github.v3+json',
      'Content-Type': 'application/json',
      'User-Agent': 'EdgeIQ-Autopilot-Security/1.0',
    },
    body: JSON.stringify({
      title,
      body,
      labels,
      assignees: [],
    }),
  });

  if (!response.ok) {
    const errorData = await response.json();
    const errorMessage = errorData.message || errorData.error || 'Unknown error';
    
    // Handle specific error cases
    if (response.status === 403) {
      throw new Error(`GitHub API forbidden: ${errorMessage}. Check token permissions (needs 'repo' scope for private repos).`);
    }
    
    if (response.status === 404) {
      throw new Error(`Repository not found: ${owner}/${repo}. Check the repository name and your token's access.`);
    }

    if (response.status === 422) {
      const errors = errorData.errors?.map(e => e.message).join(', ') || errorMessage;
      throw new Error(`GitHub validation error: ${errors}`);
    }

    throw new Error(`GitHub API error (${response.status}): ${errorMessage}`);
  }

  const data = await response.json();
  
  return {
    number: data.number,
    html_url: data.html_url,
    title: data.title,
    state: data.state,
  };
}

/**
 * Update an existing issue (add comments, change labels, close)
 */
export async function update(issueNumber, updates, owner, repo, token) {
  const url = `https://api.github.com/repos/${owner}/${repo}/issues/${issueNumber}`;

  const body = {};
  
  if (updates.comment) {
    // Add a comment to the issue
    const commentUrl = `https://api.github.com/repos/${owner}/${repo}/issues/${issueNumber}/comments`;
    await fetch(commentUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ body: updates.comment }),
    });
  }

  if (updates.labels) {
    body.labels = updates.labels;
  }

  if (updates.state) {
    body.state = updates.state; // 'open' or 'closed'
  }

  if (Object.keys(body).length === 0) {
    return { success: true, message: 'No updates provided' };
  }

  const response = await fetch(url, {
    method: 'PATCH',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/vnd.github.v3+json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(`Failed to update issue: ${errorData.message}`);
  }

  return { success: true, issueNumber };
}

/**
 * Close an issue (convenience method)
 */
export async function close(issueNumber, owner, repo, token, comment = null) {
  const updates = { state: 'closed' };
  if (comment) updates.comment = comment;
  return update(issueNumber, updates, owner, repo, token);
}

/**
 * List recent EdgeIQ issues on a repo
 */
export async function listIssues(owner, repo, token) {
  const url = `https://api.github.com/repos/${owner}/${repo}/issues?labels=edgeiq&state=open`;

  const response = await fetch(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/vnd.github.v3+json',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to list issues: ${response.status}`);
  }

  const data = await response.json();
  
  return data.map(issue => ({
    number: issue.number,
    title: issue.title,
    state: issue.state,
    labels: issue.labels.map(l => l.name),
    url: issue.html_url,
    createdAt: issue.created_at,
  }));
}

export const moduleInfo = {
  name: 'GitHub Issue Auto-Create',
  version: '1.0.0',
  description: 'Automatically create GitHub issues for security vulnerabilities',
  supportedSeverities: Object.keys(SEVERITY_LABELS),
};
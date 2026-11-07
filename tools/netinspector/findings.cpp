//=============================================================================//
//
// Findings and how they are shown
//
//=============================================================================//

#include "findings.h"

#include <algorithm>
#include <cstdio>
#include <vector>

namespace NetInspector
{

namespace
{

// The packets around a finding: a second before it, a second after it ended
constexpr double CONTEXT_SECONDS = 1.0;

struct WorstFirst
{
	template <typename Finding>
	bool operator()(const Finding *left, const Finding *right) const
	{
		if (left->severity != right->severity)
			return left->severity > right->severity;
		return left->first < right->first;
	}
};

double Seconds(uint64_t microseconds)
{
	return (double)microseconds / 1000000.0;
}

} // namespace

const char *ToString(Severity severity)
{
	switch (severity)
	{
	case Severity::Info:		return "info";
	case Severity::Medium:		return "medium";
	case Severity::High:		return "high";
	case Severity::Critical:	return "critical";
	}

	return "unknown";
}

void CFindings::Add(Severity severity, EndpointId endpoint, const std::string &kind, uint64_t time, const std::string &detail)
{
	const std::pair<EndpointId, std::string> key(endpoint, kind);
	std::map<std::pair<EndpointId, std::string>, Finding>::iterator found = m_Findings.find(key);
	if (found == m_Findings.end())
	{
		m_Findings[key] = Finding{ severity, endpoint, kind, detail, time, time, 1 };
		return;
	}

	Finding &finding = found->second;
	finding.count++;
	finding.last = std::max(finding.last, time);
	if (severity > finding.severity)
	{
		finding.severity = severity;
		finding.detail = detail;
	}
}

std::string CFindings::NextCommand(const Finding &finding, const CEndpointDirectory &endpoints, const std::string &path) const
{
	const double from = std::max(0.0, Seconds(finding.first) - CONTEXT_SECONDS);
	const double to = Seconds(finding.last) + CONTEXT_SECONDS;
	const std::string endpoint = endpoints.Describe(finding.endpoint);
	const std::string id = endpoint.substr(0, endpoint.find(' '));

	char text[1024];
	std::snprintf(text, sizeof(text), "netinspector messages \"%s\"%s%s --from %.3f --to %.3f", path.c_str(),
		finding.endpoint.IsValid() ? " --address " : "", finding.endpoint.IsValid() ? id.c_str() : "", from, to);
	return text;
}

void CFindings::Print(const CEndpointDirectory &endpoints, const CReportClock &clock, const std::string &path) const
{
	std::vector<const Finding *> sorted;
	for (const std::pair<const std::pair<EndpointId, std::string>, Finding> &entry : m_Findings)
		sorted.push_back(&entry.second);
	std::sort(sorted.begin(), sorted.end(), WorstFirst());

	for (const Finding *finding : sorted)
	{
		std::printf("%-8s %s %s\n", ToString(finding->severity), finding->endpoint.IsValid() ? endpoints.Describe(finding->endpoint).c_str() : "(no endpoint)",
			finding->kind.c_str());
		std::printf("         %ux, %s..%s: %s\n", finding->count, clock.Relative(finding->first).c_str(), clock.Relative(finding->last).c_str(), finding->detail.c_str());
		std::printf("         -> %s\n\n", NextCommand(*finding, endpoints, path).c_str());
	}
}

void CFindings::Write(const CEndpointDirectory &endpoints, const std::string &path, CJsonWriter &json) const
{
	std::vector<const Finding *> sorted;
	for (const std::pair<const std::pair<EndpointId, std::string>, Finding> &entry : m_Findings)
		sorted.push_back(&entry.second);
	std::sort(sorted.begin(), sorted.end(), WorstFirst());

	for (const Finding *finding : sorted)
	{
		json.BeginObject();
		json.Field("type", "finding");
		json.Field("severity", ToString(finding->severity));
		json.Field("endpoint", finding->endpoint.IsValid() ? endpoints.Describe(finding->endpoint) : std::string());
		json.Field("kind", finding->kind);
		json.Field("count", finding->count);
		json.Field("first", Seconds(finding->first));
		json.Field("last", Seconds(finding->last));
		json.Field("detail", finding->detail);
		json.Field("next", NextCommand(*finding, endpoints, path));
		json.EndObject();
		json.EndLine();
	}
}

} // namespace NetInspector

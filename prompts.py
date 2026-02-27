# ============================================================
#  prompts.py — AI Prompt Templates
#  Import PROMPTS and call build_analysis_prompt() to get a
#  ready-to-send prompt for any AI provider.
# ============================================================

ANALYSIS_TEMPLATE = """\
You are an expert website analyst and SEO consultant. \
Provide a comprehensive analysis of this website based on the data below.

URL: {url}

CATEGORY SCORES:
{category_scores}

TOP STRENGTHS:
{top_strengths}

CRITICAL WEAKNESSES:
{top_weaknesses}

PRIORITY ISSUES:
{priority_summary}

Please provide a detailed analysis with the following sections:

1. EXECUTIVE SUMMARY
   - Overall website health assessment
   - Key findings
   - Estimated business impact

2. STRENGTHS ANALYSIS
   - What's working well
   - Why these matter for your business
   - How to leverage these advantages

3. CRITICAL ISSUES
   - Top 5 most urgent problems
   - Business impact of each issue
   - Recommended solutions

4. PERFORMANCE OPTIMIZATIONS
   - Specific technical fixes
   - Expected performance gain
   - Implementation priority

5. SEO RECOMMENDATIONS
   - Content improvements
   - Technical SEO fixes
   - Keyword opportunities

6. SECURITY & SAFETY
   - Critical security fixes
   - Best practices to implement

7. BUSINESS & CONVERSION
   - CTA improvements
   - Trust signal additions
   - Expected conversion lift

8. IMPLEMENTATION ROADMAP
   - Quick wins (< 1 hour)
   - Short-term (1-3 days)
   - Long-term (1-4 weeks)

9. ROI PROJECTIONS
   - Expected traffic increase
   - Conversion improvement estimate
   - Timeline for results

Be specific, actionable, and data-driven.\
"""

FALLBACK_TEMPLATE = """\
🔍 AI-POWERED WEBSITE ANALYSIS

EXECUTIVE SUMMARY
Based on comprehensive analysis of {url}, we've examined 115+ items across 7 categories.

OVERALL HEALTH: {overall_health}/100

KEY STRENGTHS
{strengths}

CRITICAL ISSUES
{weaknesses}

TOP RECOMMENDATIONS
{recommendations}

QUICK WINS
{quick_wins}

EXPECTED ROI
Addressing priority issues could improve overall site health by 15-25% within 3 months.\
"""

SYSTEM_PROMPT = (
    "You are an expert website analyst and SEO consultant. "
    "Provide detailed, actionable insights based on the data provided."
)

# Per-provider model defaults (override in config.py if needed)
PROVIDER_DEFAULTS = {
    "groq":        {"model": "mixtral-8x7b-32768",              "temperature": 0.7, "max_tokens": 2000},
    "openrouter":  {"model": "mistralai/mistral-7b-instruct",   "temperature": 0.7, "max_tokens": 2000},
    "cohere":      {"model": "command",                          "temperature": 0.7, "max_tokens": 2000},
    "glm5":        {"model": "glm-4",                            "temperature": 0.7, "max_tokens": 2000},
    "gemini":      {"model": "gemini-2.0-flash-exp",             "temperature": 0.7, "max_tokens": 2000},
}


def build_analysis_prompt(url: str, categories: list, strengths: list,
                          weaknesses: list, priority_items: list) -> str:
    """Return a filled-in analysis prompt ready to send to any AI provider."""
    category_scores = "\n".join(f"• {c['name']}: {c['score']}/100" for c in categories)
    top_strengths   = "\n".join(f"• {s}" for s in strengths[:5]) or "• None identified"
    top_weaknesses  = "\n".join(f"• {w}" for w in weaknesses[:5]) or "• None identified"
    priority_summary = "".join(
        f"• {p['name']} (Score: {p['score']}) — {p.get('action', 'Needs attention')}\n"
        for p in priority_items[:5]
    )

    return ANALYSIS_TEMPLATE.format(
        url=url,
        category_scores=category_scores,
        top_strengths=top_strengths,
        top_weaknesses=top_weaknesses,
        priority_summary=priority_summary,
    )


def build_fallback_analysis(url: str, categories: list, strengths: list,
                            weaknesses: list, priority_items: list) -> str:
    """Return a plain-text fallback analysis when all AI providers fail."""
    strengths_text = "\n".join(f"• {s}" for s in strengths[:5]) or "• No significant strengths identified"
    weaknesses_text = "\n".join(f"• {w}" for w in weaknesses[:5]) or "• No critical issues found"

    recommendations = "\n".join(
        f"• {p['name']}: {p.get('action', 'Address this issue')}"
        for p in priority_items[:5]
    )
    quick_wins = "\n".join(
        f"• {p['name']} — fixable in {p.get('time', '1-2 hours')}"
        for p in priority_items[:3]
        if p.get("effort") == "low"
    ) or "• Review priority items above"

    return FALLBACK_TEMPLATE.format(
        url=url,
        overall_health=categories[0]["score"] if categories else 70,
        strengths=strengths_text,
        weaknesses=weaknesses_text,
        recommendations=recommendations,
        quick_wins=quick_wins,
    )

# The Threat Hunter's Cookbook - Summary

## Metadata
- **Title**: The Threat Hunter's Cookbook
- **Authors**: Dr. Ryan Fetterman and Sydney Marrone
- **Publisher**: Splunk SURGe
- **Foreword**: Ryan Kovar
- **Location**: `/Users/sydney/Downloads/threat-hunters-cookbook.pdf`

## Overview

The Threat Hunter's Cookbook is a practical, recipe-based guide for conducting threat hunting using Splunk's Search Processing Language (SPL). It bridges the gap between the theoretical PEAK Threat Hunting Framework and the practical implementation using Splunk.

## Core Philosophy

**"Threat hunting is like baking bread"** - Ryan Kovar's foreword emphasizes that threat hunting boils down to simple questions:
- Are you looking for a deviation?
- Are you working with new data?
- Are you searching for commonalities?
- Are you hunting for a known indicator?

## Book Structure

### 7 Primary Methods (Categories)

1. **Searching and Filtering** - Your chef's knife for slicing and extracting data
2. **Sorting and Stacking** - Finding highest volume or rarest values
3. **Grouping** - Connecting complementary actions and events
4. **Forecasting and Anomaly Detection** - Finding out-of-the-ordinary events
5. **Clustering** - Automatically measuring associations between events
6. **Exploratory Data Analysis and Visualization** - Establishing baselines
7. **Combined Methods** - Master class in multi-stage hypotheses and advanced techniques

## Key Concepts

### Choosing the Right Recipe

The book provides a **decision flow chart** (pg 4) to help select the appropriate hunting method:

- **Hunting for hard-coded strings/indicators?** → Searching and Filtering
- **Hunting involves highest/lowest/common/rare values?** → Sorting and Stacking
- **Hunting for activity linked by common entity?** → Grouping
- **Hunting for deviations from a pattern?** → Forecasting/Anomaly Detection or Clustering
- **Baselining/Exploring new data?** → Exploratory Data Analysis
- **Data has implicit complexity or previous methods not working?** → Model-Assisted Methods

### Identification vs. Classification

Break threat hunting into two phases:
1. **Identification** - Create the most specific search possible (high precision) while capturing all potential events (high recall)
2. **Classification** - Distinguish between benign and malicious events

## Method Details

### 1. Searching and Filtering (pg 22-25)

**SPL Functions**: `metadata`, `datamodel`, `xyseries`, `untable`, `eval`, logical operators, relational operators, `lookup`, `regex`, `rex`

**Recipes**:
- Filtering and combining search logic
- Extracting strings or matching text patterns
- Wildcard-matching strings
- Searching against tables or indicator lists
- Optimizing searches with `tstats` and `datamodel`
- Creating or updating fields on-the-fly

**Chef's Tips**:
- Time is a powerful filter - select the smallest appropriate window
- Be as specific as possible (index, sourcetype, host)
- Search by inclusion is better than exclusion
- Consider the order of your search operations
- Minimize wildcards

### 2. Sorting and Stacking (pg 26-27)

**SPL Functions**: `stats`, `top`, `rare`, `sort`, `eventstats`, `streamstats`

**Also known as**: "stack counting" or "frequency analysis"

**Recipes**:
- Identifying high-volume activity
- Isolating rare events and values
- Sorting results
- Calculating search-time statistics

**Use Cases**:
- Find rare processes or executables
- Find highly active users or high event volume
- Assess high and low trends over time

**Chef's Tips**:
- Stack across multiple fields with `stats` by adding fields after the BY clause
- Default limit is 10000; use `limit=0` to return all results

### 3. Grouping (pg 27-28)

**SPL Functions**: `bin`, `stats` (values, dc, count/avg/min/max), `join`, `transaction`

**Use for**:
- Grouping activity across adversarial tactics (Initial Access → Privilege Escalation)
- Connecting technique sequences (encoded command execution → malware download)
- Linking events by common entities (account, host, asset, time)

**Recipes**:
- Grouping by field values
- Reviewing field values by group
- Counting by group
- Merging groups by common field

**Chef's Tips**:
- Working with time influences how you group events
- Consider time bucketing: `| bucket _time span=1m as minute`
- For risk-based alerting, hunt in your risk index
- Can stack multiple fields similar to stats

### 4. Forecasting and Anomaly Detection (pg 29-31)

**SPL Functions**: `fillnull`, `timechart`, `eventstats`, `eval`, `anomalydetection`

**Algorithms**: DensityFunction, OneClassSVM, ARIMA, StateSpaceForecast

**Anomaly Detection Methods Compared**:

1. **Standard Deviation Method**
   - Threshold: 2, 2.5, or 3 standard deviations from mean
   - ~95% of data lies within 2 standard deviations

2. **Interquartile Range (IQR) Method**
   - Outliers: Q1 - 1.5×IQR or Q3 + 1.5×IQR
   - More robust to extreme values

3. **Z-Score Method**
   - Threshold: Z-score > 3 or < -3
   - Measures standard deviations from mean

4. **Modified Z-Score**
   - Uses median and MAD instead of mean and standard deviation
   - Threshold: 3.5 or higher
   - More robust to outliers

**Recipes**:
- Comparing anomaly calculation methods
- Using built-in anomaly detection
- Model-assisted methods (DensityFunction, OneClassSVM, ARIMA, StateSpaceForecast)
- Fitting an anomaly detection model

**Chef's Tips**:
- Mean, median, and mode provide key insights when baselining
- Adjust outlier thresholds based on result quality
- Handle nulls deliberately with `fillnull`
- Consider seasonality in time series analysis
- Remember: an outlier is statistical, an anomaly is context-dependent

### 5. Clustering (pg 31-32)

**SPL Functions**: `stats`, `cluster`, `fields`, `kmeans`, `xyseries`

**Algorithms**: K-Means, DBSCAN, PCA, TFIDF

**Use for**:
- Clustering JA3 signatures to distinguish malicious vs. legitimate executables
- Clustering encoded URI strings and user-agents
- Grouping similar categorical or numerical data

**Difference from Grouping**:
- Clustering: algorithms determine the groups automatically (unsupervised)
- Grouping: categories are predefined

**Recipes**:
- Grouping via categorical fields
- Pivoting a statistics table
- Model-assisted methods (K-Means, DBSCAN)

**Chef's Tips**:
- Use dimensionality reduction (PCA) for high-dimensional data
- Cluster text-based fields by encoding numerically (TFIDF)
- Vectorize strings to measure distance or similarity

### 6. Exploratory Data Analysis and Visualization (pg 33-36)

**SPL Functions**: `fieldsummary`, `transpose`, `chart`, `bin`, `metadata`, `timechart`, `sparkline`

**Visualizations**: Scatter Plot, Box Plot, Histograms

**Recipes**:
- Transforming data (transpose)
- Exploring new data sources (fieldsummary, metadata)
- Uncovering relationships between variables (scatter plots)
- Visualizing distributions (box plots, histograms)
- Working with _time

**Box Plot Statistics (Five-Number Summary)**:
- Minimum value
- Second quartile (25th percentile)
- Median value
- Third quartile (75th percentile)
- Maximum value

**Chef's Tips**:
- Start with `fieldsummary` to shortcut statistics calculation
- Default search order is reverse chronological; use `| sort -_time` or `| reverse`
- Use scatter plots to evaluate model predictions
- Box plots help visualize normal activity vs. outliers

### 7. Combined Methods (pg 37-43)

**SPL Functions**: `iplocation`, `geostats`, `appendpipe`, `outputlookup`

**Algorithms**: DecisionTreeClassifier, GradientBoostingClassifier, LogisticRegression, RandomForestClassifier

**Advanced Recipes**:
- **C2 Beaconing Detection**: Low variance in time between connections
- **DNS Exfiltration**: High packet size + high event volume
- **Geographic Analysis**: Using `iplocation` and `geostats`
- **Baseline Detection**: First-time domain visits, user-agent analysis, egress communication

**Model-Assisted Methods**:

**Classification Algorithms**:
- DecisionTreeClassifier - Tree-based splitting
- GradientBoostingClassifier - Ensemble of weak learners
- LogisticRegression - Binary classification
- RandomForestClassifier - Multiple decision trees
- Deep Learning - Neural networks (LSTM, MLP, RNN)

**Pre-trained Models Available**:
- Detect Suspicious TXT Records (LSTM)
- Detect DNS Data Exfiltration (MLP)
- Detect Suspicious Processes (RNN)
- Detect Domain Generation Algorithms (LSTM)
- NLP-Based Risky SPL Detection (Transformer)

**Chef's Tips**:
- Understand data science fundamentals: imputation, normalization, scaling, encoding
- Ask if the problem needs machine learning before building a model
- Use ML only when:
  - Simpler methods won't work equally well
  - Data is complex and requires pre-processing
  - ML offers novel discovery opportunities

## Special Ingredients: Splunkbase Add-ons

### URL Toolbox
- Parse URLs and complicated TLDs using Mozilla Public Suffix List
- Shannon entropy calculation
- Levenshtein distance for homoglyph/spoofing detection
- Macros: `ut_parse_extended`, `ut_shannon`, `ut_levenshtein`

**Example Use Cases**:
- Detecting high-entropy randomized subdomains
- Hunting DNScat2 exfiltration
- Finding spoofed/homoglyph domains

### PSTree for Splunk
- Reconstruct process trees from Sysmon EventCode 1
- Visualize parent-child process relationships
- Hunt suspicious processes from unusual directories

**Example Output**:
```
WmiPrvSE.exe (2240)
|--- powershell.exe (4976)
    |--- eventvwr.exe (3800)
        |--- powershell.exe (4468)
            |--- ftp.exe (4540)
```

### Other Recommended Add-ons:
- Event Timeline Viz
- Configuration Manager (Conf Manager)
- Splunk App for Behavioral Profiling
- Tuning Framework for Splunk
- Splunk Enterprise Security
- SA-Investigator for Enterprise Security
- SA-DetectionInsights
- Insights Suite for Splunk (IS4S)

## Integration with PEAK Framework

The Cookbook is **designed to complement the PEAK Framework**:
- PEAK provides the structure and methodology (Prepare, Execute, Act with Knowledge)
- The Cookbook provides the practical SPL implementation
- Both created by the Splunk SURGe team (Ryan Fetterman, Sydney Marrone, David Bianco)

**Hunt Type Correlations**:
- **Hypothesis-based hunts**: Often use Searching/Filtering, Grouping
- **Baseline hunts**: Often use EDA, Sorting/Stacking
- **Model-Assisted (M-ATH)**: Often use Anomaly Detection, Clustering, Classification

## Quick Reference Chart (pg 44)

| Method | Use When | Key SPL Functions |
|--------|----------|-------------------|
| Searching & Filtering | Hard-coded strings/indicators | `metadata`, `datamodel`, `regex`, `rex`, `lookup` |
| Sorting & Stacking | Highest/lowest/rare values | `stats`, `top`, `rare`, `sort`, `eventstats` |
| Grouping | Common entity linking | `bin`, `stats`, `join`, `transaction` |
| Forecasting & Anomaly | Deviations from pattern | `timechart`, `anomalydetection`, `fillnull` |
| Clustering | Pattern not defined | `cluster`, `kmeans`, `fields` |
| EDA & Visualization | Baselining/exploring | `fieldsummary`, `transpose`, `chart`, `metadata` |
| Combined Methods | Complex/multi-stage | `iplocation`, `geostats`, `appendpipe` |

## Key Takeaways

1. **Follow the Recipe, Then Experiment**: Like baking, master the basics first, then get creative
2. **Adapt to Your Environment**: Examples showcase possibilities; modify for your field names and values
3. **Use the Right Tool**: Specialized tools often better than bash commands
4. **Document Your Work**: Follow PEAK template for hunt documentation
5. **Measure Success**: Track metrics beyond just incident count (detections created, gaps closed)
6. **Think Behavioral**: Hunt at the top of the Pyramid of Pain (TTPs, not IOCs)

## Notable Examples and Patterns

### C2 Beaconing Detection (pg 37)
```spl
tag=dns message_type="QUERY"
| streamstats current=f last(_time) as last_time by query
| eval gap=last_time - _time
| stats count avg(gap) AS AverageBeaconTime var(gap) AS VarianceBeaconTime BY query
| where VarianceBeaconTime < 60 AND count > 2
```

### DNS Exfiltration Detection (pg 37-38)
```spl
tag=dns message_type="QUERY"
| mvexpand query
| eval queryLength=len(query)
| stats last(query) as sample count by queryLength, src
| sort -queryLength, count
```

### New Domain Baseline (pg 25)
Uses `outputlookup` to maintain a baseline of previously seen domains, then compares current traffic to identify first-time connections.

### Egress Communication Baseline (pg 39-40)
Maintains baseline of source-destination IP pairs to detect first-time egress communications from internal servers.

## Contributors

- David Bianco
- Johan Bjerke
- Robin Burkett
- James Callahan
- Tyne Darke
- Derek Du
- Jordan Fuentes
- Megan Jooste
- Audra Streetman
- Jesse Trucks

## Resources

- **PEAK Threat Hunting Framework**: Splunk SURGe official publication
- **Splunk Machine Learning Toolkit (MLTK)**: Advanced data science methods
- **Splunk App for Data Science and Deep Learning (DSDL)**: Jupyter Lab environment
- **Splunkbase**: Community apps and add-ons
- **Splunk Threat Research Team**: Pre-built hunting queries

## How This Integrates with MCP Server

The Threat Hunter's Cookbook enhances this MCP server by:

1. **Practical SPL Examples**: Provides concrete implementation patterns for PEAK hunts
2. **Method Selection Guidance**: Decision flow helps choose the right hunting approach
3. **Splunk-Specific Techniques**: Optimizations like `tstats`, `datamodel`, accelerated searches
4. **Advanced Analytics**: ML/clustering methods that can inform hunt strategy
5. **Real-World Recipes**: Battle-tested patterns from Splunk SURGe team

## Usage Recommendations

### For Threat Hunters:
1. Start with the decision flow chart to select your method
2. Review the relevant method section for conceptual understanding
3. Adapt the recipes to your data sources and field names
4. Combine methods for complex hunts
5. Document findings using PEAK template

### For Tool Development:
1. Use recipes as test cases for MCP tool functionality
2. Incorporate anomaly detection algorithms (DensityFunction, ARIMA, etc.)
3. Provide method selection guidance based on hunt goals
4. Support baseline creation and maintenance patterns
5. Enable model-assisted hunting workflows

### For Hunt Automation:
1. Baseline hunts → Automate with scheduled searches
2. Anomaly detection → Implement with threshold tuning
3. Classification → Deploy pre-trained models where applicable
4. Maintain lookup tables for known good/bad indicators
5. Track hunt metrics and maturity (HMM levels)

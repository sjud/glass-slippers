use std::collections::{HashMap, HashSet};

#[cfg(feature = "ssr")]
use crate::{clickhouse_client, TraceDigested};
use chrono::DateTime;
use leptos::prelude::*;
use leptos_meta::{provide_meta_context, MetaTags, Stylesheet, Title};
use leptos_router::{
    components::{Route, Router, Routes},
    StaticSegment,
};
use serde::{Deserialize, Serialize};

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <AutoReload options=options.clone() />
                <HydrationScripts options />
                <MetaTags />
            </head>
            <body>
                <App />
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/tracing-ui.css" />

        // sets the document title
        <Title text="Welcome to Leptos" />

        // content for this welcome page
        <Router>
            <main>
                <Routes fallback=|| "Page not found.".into_view()>
                    <Route path=StaticSegment("") view=HomePage />
                </Routes>
            </main>
        </Router>
    }
}

/// Renders the home page of your application.
#[component]
fn HomePage() -> impl IntoView {
    let resource = Resource::new(|| (), |_| list_requests());
    // TODO get sessions and then get requests per session.
    view! {
        <Suspense fallback=move || view! { <p>"Loading (Suspense Fallback)..."</p> }>
        // or you can use `Suspend` to read resources asynchronously
        {move || Suspend::new(async move {
          if let Ok(span_trees) = resource.await {
            span_trees.into_iter().map(|span_tree|
            view!{<SpanTreeComponent span_tree/>}).collect_view()
          } else {
            panic!("huh")
        }})}
      </Suspense>
    }
}
#[server]
pub async fn list_requests() -> Result<Vec<SpanTree>, ServerFnError> {
    let client = clickhouse_client().await?;
    let traces = client.get_traces_with_limit(100).await?;
    let mut grouped: HashMap<u64, Vec<TraceDigested>> = HashMap::new();

    for item in traces {
        grouped
            .entry(item.request_id)
            .or_insert_with(Vec::new)
            .push(item);
    }

    Ok(grouped.into_values().map(SpanTree::from).collect::<_>())
}
#[cfg(feature = "ssr")]
impl From<Vec<TraceDigested>> for SpanTree {
    fn from(value: Vec<TraceDigested>) -> Self {
        println!("value {value:#?}");
        // split up spans and events.
        let mut events = Vec::new();
        let mut spans = Vec::new();
        for trace in value {
            if trace.is_span() {
                spans.push(SpanUiData::from(trace));
            } else {
                events.push(EventUiData::from(trace));
            }
        }
        // create a span tree for each span.
        let mut span_trees = spans
            .clone()
            .into_iter()
            .map(|span| {
                (
                    span.name.clone(),
                    SpanTree {
                        span,
                        ..Default::default()
                    },
                )
            })
            .collect::<HashMap<String, SpanTree>>();
        println!("span_trees: {span_trees:#?}");
        // assign events to each spantree.
        for event in events {
            let span_tree = span_trees.get_mut(&event.current_span).unwrap();
            span_tree.events.push(event);
        }

        build_tree_backwards(&spans, &mut span_trees)
    }
}

#[cfg(feature = "ssr")]
pub fn build_tree_backwards(
    spans: &Vec<SpanUiData>,
    span_trees: &mut HashMap<String, SpanTree>,
) -> SpanTree {
    // find the parent child relationship of each node
    let mut parent_children_map: HashMap<String, Vec<String>> = HashMap::new();
    for span in spans.iter() {
        if let Some(child_list) = parent_children_map.get_mut(&span.parent) {
            child_list.push(span.name.clone())
        } else {
            parent_children_map.insert(span.parent.clone(), vec![span.name.clone()]);
        }
    }
    // start by creating a childless list of every childless span.
    let mut childless = Vec::new();
    for span in spans.iter() {
        if !parent_children_map.contains_key(&span.name) {
            childless.push(span.clone());
        }
    }
    // iterate through the childless list
    while let Some(span) = childless.pop() {
        // remove the childless spantree from the span_trees map
        let span_tree = span_trees
            .remove(&span.name)
            .expect(&format!("{} not found in span_trees", span.name));
        // return root, if is root then parent = root. lol
        if span_tree.span.parent == "root" {
            return span_tree;
        }
        // get a mutable reference to the parent of the childless tree
        let parent = span_trees
            .get_mut(&span.parent)
            .expect(&format!("{} to exist in span trees", &span.parent));
        // update the parent
        parent.children.push(span_tree);
        // now we find the span's parent's child list, and we remove the span we just removed from the tree.
        let children_list = parent_children_map.get_mut(&span.parent).unwrap();
        let i = children_list
            .iter()
            .position(|name| name == &span.name)
            .unwrap();
        children_list.remove(i);
        // if we just removed the last item from the children of the parent, the parent is childless, we remove the parent from the relationship map
        // and we add the parent to the childless list.
        if children_list.is_empty() {
            parent_children_map.remove(&span.parent);
            let span = spans
                .iter()
                .find(|new_span| new_span.name == span.parent)
                .unwrap();
            childless.push(span.clone());
        }
    }
    panic!("expecting childless span with name of root");
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum UiData {
    Event(EventUiData),
    Span(SpanUiData),
}
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct EventUiData {
    pub current_span: String,
    pub level: UiTraceLevel,
    pub request_id: u64,
    pub fields: Vec<(String, String)>,
    pub timestamp: u64,
}
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SpanUiData {
    pub name: String,
    pub parent: String,
    pub level: UiTraceLevel,
    pub fields: Vec<(String, String)>,
    pub request_id: u64,
    pub timestamp: u64,
}
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SpanTree {
    pub span: SpanUiData,
    pub children: Vec<SpanTree>,
    pub events: Vec<EventUiData>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub enum UiTraceLevel {
    #[default]
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR,
}
impl UiTraceLevel {
    pub fn bg_color(&self) -> &'static str {
        match &self {
            UiTraceLevel::TRACE => "bg-grey-300",
            UiTraceLevel::DEBUG => "bg-blue-300",
            UiTraceLevel::INFO => "bg-green-300",
            UiTraceLevel::WARN => "bg-yellow-300",
            UiTraceLevel::ERROR => "bg-red-300",
        }
    }
}
#[component]
pub fn SpanTreeComponent(span_tree: SpanTree) -> impl IntoView {
    let SpanTree {
        span:
            SpanUiData {
                name,
                parent,
                level,
                fields,
                request_id,
                timestamp,
            },
        children,
        events,
    } = span_tree;
    let values = fields
        .into_iter()
        .map(|v| view! { <p>{format!("{} : {}", v.0, v.1)}</p> })
        .collect::<Vec<_>>();
    let events = events
        .into_iter()
        .map(|event| view! {<Event event/>})
        .collect::<Vec<_>>();
    let children = children
        .into_iter()
        .map(|span_tree| view! {<SpanTreeComponent span_tree/>}.into_any())
        .collect::<Vec<_>>();
    view! {
        <div>
        <div class=format!("{}", level.bg_color())>
            <p class="font-bold">{name}</p>
            {values}
            {events}
            {children}
        </div>
    </div>
    }
    .into_view()
}

#[component]
pub fn Event(event: EventUiData) -> impl IntoView {
    let EventUiData {
        current_span,
        level,
        request_id,
        fields,
        timestamp,
    } = event;
    let values = fields
        .into_iter()
        .map(|v| view! { <p>{format!("{} : {}", v.0, v.1)}</p> })
        .collect::<Vec<_>>();
    let datetime = DateTime::from_timestamp(timestamp as i64, 0).unwrap();
    view! {
        <div class=format!("{}", level.bg_color())>
            <div>{format!("request_id {request_id} event_time {datetime}")}</div>
            {values}
        </div>
    }
}

#[cfg(test)]
pub mod tests {
    use crate::DigestedLevel;

    use super::*;
    use uuid::Uuid;
    #[tokio::test]
    pub async fn list_requests() {
        let traces = vec![
            TraceDigested {
                browser_session_id: 0,
                request_id: 0,
                timestamp: 1728340478,
                auth_id: Uuid::nil(),
                target: "dev_example".to_string(),
                span_name: "http_request".to_string(),
                span_parent: "root".to_string(),
                level: DigestedLevel::INFO,
                current_span: "INFO".to_string(),
                fields: vec![("message".to_string(), "new".to_string())],
            },
            TraceDigested {
                browser_session_id: 0,
                request_id: 1,
                timestamp: 1728340478,
                auth_id: Uuid::nil(),
                target: "dev_example".to_string(),
                span_name: "http_request".to_string(),
                span_parent: "root".to_string(),
                level: DigestedLevel::INFO,
                current_span: "INFO".to_string(),
                fields: vec![("message".to_string(), "new".to_string())],
            },
            TraceDigested {
                browser_session_id: 0,
                request_id: 2,
                timestamp: 1728340478,
                auth_id: Uuid::nil(),
                target: "dev_example".to_string(),
                span_name: "http_request".to_string(),
                span_parent: "root".to_string(),
                level: DigestedLevel::INFO,
                current_span: "INFO".to_string(),
                fields: vec![("message".to_string(), "new".to_string())],
            },
            TraceDigested {
                browser_session_id: 0,
                request_id: 3,
                timestamp: 1728340478,
                auth_id: Uuid::nil(),
                target: "dev_example".to_string(),
                span_name: "http_request".to_string(),
                span_parent: "root".to_string(),
                level: DigestedLevel::INFO,
                current_span: "INFO".to_string(),
                fields: vec![("message".to_string(), "new".to_string())],
            },
            TraceDigested {
                browser_session_id: 0,
                request_id: 4,
                timestamp: 1728340478,
                auth_id: Uuid::nil(),
                target: "dev_example".to_string(),
                span_name: "http_request".to_string(),
                span_parent: "root".to_string(),
                level: DigestedLevel::INFO,
                current_span: "INFO".to_string(),
                fields: vec![("message".to_string(), "new".to_string())],
            },
            TraceDigested {
                browser_session_id: 0,
                request_id: 5,
                timestamp: 1728340482,
                auth_id: Uuid::nil(),
                target: "dev_example".to_string(),
                span_name: "http_request".to_string(),
                span_parent: "root".to_string(),
                level: DigestedLevel::INFO,
                current_span: "INFO".to_string(),
                fields: vec![("message".to_string(), "new".to_string())],
            },
            TraceDigested {
                browser_session_id: 0,
                request_id: 5,
                timestamp: 1728340482,
                auth_id: Uuid::nil(),
                target: "dev_example::app".to_string(),
                span_name: "__click_me".to_string(),
                span_parent: "\"http_request\"".to_string(),
                level: DigestedLevel::INFO,
                current_span: "INFO".to_string(),
                fields: vec![("message".to_string(), "new".to_string())],
            },
            TraceDigested {
                browser_session_id: 0,
                request_id: 5,
                timestamp: 1728340482,
                auth_id: Uuid::nil(),
                target: "dev_example::app".to_string(),
                span_name: "click_me_inner".to_string(),
                span_parent: "\"__click_me\"".to_string(),
                level: DigestedLevel::INFO,
                current_span: "INFO".to_string(),
                fields: vec![("message".to_string(), "new".to_string())],
            },
            TraceDigested {
                browser_session_id: 0,
                request_id: 6,
                timestamp: 1728340483,
                auth_id: Uuid::nil(),
                target: "dev_example".to_string(),
                span_name: "http_request".to_string(),
                span_parent: "root".to_string(),
                level: DigestedLevel::INFO,
                current_span: "INFO".to_string(),
                fields: vec![("message".to_string(), "new".to_string())],
            },
            TraceDigested {
                browser_session_id: 0,
                request_id: 6,
                timestamp: 1728340483,
                auth_id: Uuid::nil(),
                target: "dev_example::app".to_string(),
                span_name: "__click_me".to_string(),
                span_parent: "\"http_request\"".to_string(),
                level: DigestedLevel::INFO,
                current_span: "INFO".to_string(),
                fields: vec![("message".to_string(), "new".to_string())],
            },
            TraceDigested {
                browser_session_id: 0,
                request_id: 6,
                timestamp: 1728340483,
                auth_id: Uuid::nil(),
                target: "dev_example::app".to_string(),
                span_name: "click_me_inner".to_string(),
                span_parent: "\"__click_me\"".to_string(),
                level: DigestedLevel::INFO,
                current_span: "INFO".to_string(),
                fields: vec![("message".to_string(), "new".to_string())],
            },
        ];
    }
}

package v3

import (
	v3 "envoyproxy.io/deps/cncf/xds/go/xds/type/matcher/v3"
)

// [#protodoc-title: Meta Protocol Proxy Route Configuration]
// The meta protocol proxy makes use of the `xds matching API` for routing configurations.
//
// In the below example, we combine a top level tree matcher with a linear matcher to match
// the incoming requests, and send the matching requests to v1 of the upstream service.
//
// name: demo-v1
// route:
//   matcher_tree:
//     input:
//       name: request-service
//       typed_config:
//         "@type": type.googleapis.com/envoy.extensions.filters.network.meta_protocol_proxy.matcher.v3.ServiceMatchInput
//     exact_match_map:
//       map:
//         org.apache.dubbo.samples.basic.api.DemoService:
//           matcher:
//             matcher_list:
//               matchers:
//               - predicate:
//                   and_matcher:
//                     predicate:
//                     - single_predicate:
//                         input:
//                           name: request-properties
//                           typed_config:
//                             "@type": type.googleapis.com/envoy.extensions.filters.network.meta_protocol_proxy.matcher.v3.PropertyMatchInput
//                             property_name: version
//                         value_match:
//                           exact: v1
//                     - single_predicate:
//                         input:
//                           name: request-properties
//                           typed_config:
//                             "@type": type.googleapis.com/envoy.extensions.filters.network.meta_protocol_proxy.matcher.v3.PropertyMatchInput
//                             property_name: user
//                         value_match:
//                           exact: john
//                 on_match:
//                   action:
//                     name: route
//                     typed_config:
//                       "@type": type.googleapis.com/envoy.extensions.filters.network.meta_protocol_proxy.matcher.action.v3.routeAction
//                       cluster: outbound|20880|v1|org.apache.dubbo.samples.basic.api.demoservice
// [#not-implemented-hide:]
#RouteConfiguration: {
	"@type": "type.googleapis.com/envoy.extensions.filters.network.meta_protocol_proxy.v3.RouteConfiguration"
	// The name of the route configuration. For example, it might match route_config_name in
	// envoy.extensions.filters.network.meta_protocol_proxy.v3.Rds.
	name?: string
	// The match tree to use when resolving route actions for incoming requests.
	route?: v3.#Matcher
}

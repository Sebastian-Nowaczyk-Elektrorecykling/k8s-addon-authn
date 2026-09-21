this is a repository that is to be deployed on a cluster where https://github.com/Sebastian-Nowaczyk-Elektrorecykling/minimum-k8s-net-elektro and https://github.com/Sebastian-Nowaczyk-Elektrorecykling/k8s-addon-storage are already applied

it should be based on authentik, OpenFGA, Heimdall and oauth2-proxy
it should add routes to sevices added by this and previous repositories and protect them with SSO

administrator tools should be under .admin.internal
things to be used by ordinary users go under .internal directly

OpenFGA model should for start contain user (for human users), agent (for AI agents, service accounts and other entities that cannot use the browser login) and clustersite (representation of a domain served by the cluster)
users and agents should be able to be given access to a set of clustersites

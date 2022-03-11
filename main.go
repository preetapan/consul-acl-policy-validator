package main

import (
	"fmt"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"log"
)

type ACLPolicy struct {
	ACL             string         `hcl:"acl,expand"`
	Nodes           []*NodeRule    `hcl:"node,expand"`
	NodePrefixes    []*NodeRule    `hcl:"node_prefix,expand"`
	Services        []*ServiceRule `hcl:"service,expand"`
	ServicePrefixes []*ServiceRule `hcl:"service_prefix,expand"`
}

type ServiceRule struct {
	Name   string `hcl:",key"`
	Policy string `hcl:"policy"`

	// Intentions is the policy for intentions where this service is the
	// destination. This may be empty, in which case the Policy determines
	// the intentions policy.
	Intentions string `hcl:"intentions"`
}

// NodeRule represents a rule for a node
type NodeRule struct {
	Name   string `hcl:",key"`
	Policy string `hcl:"policy"`
}

var aclPolicySchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{
			Type: "policy",
		},
	},
}

var policyBlockSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "node"},
		{Type: "node_prefix"},
		{Type: "service"},
		{Type: "service_prefix"},
	},
	Attributes: []hcl.AttributeSchema{
		{Name: "acl", Required: true},
	},
}

var nodeRuleBlockSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "node"},
	},
	Attributes: []hcl.AttributeSchema{
		{Name: "name", Required: false},
		{Name: "policy", Required: true},
	},
}

var nodePrefixBlockSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "node_prefix"},
	},
	Attributes: []hcl.AttributeSchema{
		{Name: "name", Required: false},
		{Name: "policy", Required: true},
	},
}

var serviceRuleBlockSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "service"},
	},
	Attributes: []hcl.AttributeSchema{
		{Name: "name", Required: false},
		{Name: "policy", Required: true},
	},
}

var servicePrefixBlockSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "service_prefix"},
	},
	Attributes: []hcl.AttributeSchema{
		{Name: "name", Required: false},
		{Name: "policy", Required: true},
	},
}

// Parse will parse file content into valid config.
func Parse(filename string) (c *ACLPolicy, errs []error) {
	parser := hclparse.NewParser()
	file, parseDiags := parser.ParseHCLFile(filename)

	if parseDiags.HasErrors() {
		return nil, parseDiags.Errs()
	}

	bodyCont, confDiags := file.Body.Content(aclPolicySchema)
	if confDiags.HasErrors() {
		return nil, confDiags.Errs()
	}

	var aclPolicy = &ACLPolicy{}

	blockCfg, blockDiags := bodyCont.Blocks[0].Body.Content(policyBlockSchema)
	if blockDiags.HasErrors() {
		return nil, blockDiags.Errs()
	}
	aclAttr := blockCfg.Attributes["acl"]
	acl := ""
	decodeDiags := gohcl.DecodeExpression(aclAttr.Expr, nil, &acl)
	if decodeDiags.HasErrors() {
		log.Fatalf("decode acl attr error: %v", decodeDiags)
	}
	aclPolicy.ACL = acl

	// Validate Node Rules if present
	for _, block := range blockCfg.Blocks {
		switch block.Type {
		case "node":
			parseNodeBlock(block.Body, aclPolicy)
			continue
		case "node_prefix":
			parseNodePrefixBlock(block.Body, aclPolicy)
			continue
		case "service":
			parseServiceBlock(block.Body, aclPolicy)
			continue
		case "service_prefix":
			parseServicePrefixBlock(block.Body, aclPolicy)
			continue
		}
	}

	return aclPolicy, errs
}

func parseNodeBlock(body hcl.Body, aclPolicy *ACLPolicy) {
	blockNode, blockNodeDiags := body.Content(nodeRuleBlockSchema)
	if blockNodeDiags.HasErrors() {
		log.Fatalf("block content error: %v", blockNodeDiags)
	}
	name := ""
	policy := ""
	if attr, exists := blockNode.Attributes["name"]; exists {
		decodeDiags := gohcl.DecodeExpression(attr.Expr, nil, &name)
		if decodeDiags.HasErrors() {
			log.Fatalf("decode name attr error: %v", decodeDiags)
		}
	}
	if attr, exists := blockNode.Attributes["policy"]; exists {
		decodeDiags := gohcl.DecodeExpression(attr.Expr, nil, &policy)
		if decodeDiags.HasErrors() {
			log.Fatalf("decode policy attr error: %v", decodeDiags)
		}
	}
	aclPolicy.Nodes = append(aclPolicy.Nodes, &NodeRule{Policy: policy, Name: name})
}

func parseNodePrefixBlock(body hcl.Body, aclPolicy *ACLPolicy) {
	blockNode, blockNodeDiags := body.Content(nodePrefixBlockSchema)
	if blockNodeDiags.HasErrors() {
		log.Fatalf("block content error: %v", blockNodeDiags)
	}
	name := ""
	policy := ""
	if attr, exists := blockNode.Attributes["name"]; exists {
		decodeDiags := gohcl.DecodeExpression(attr.Expr, nil, &name)
		if decodeDiags.HasErrors() {
			log.Fatalf("decode name attr error: %v", decodeDiags)
		}
	}
	if attr, exists := blockNode.Attributes["policy"]; exists {
		decodeDiags := gohcl.DecodeExpression(attr.Expr, nil, &policy)
		if decodeDiags.HasErrors() {
			log.Fatalf("decode policy attr error: %v", decodeDiags)
		}
	}
	aclPolicy.NodePrefixes = append(aclPolicy.NodePrefixes, &NodeRule{Policy: policy, Name: name})
}

func parseServiceBlock(body hcl.Body, aclPolicy *ACLPolicy) {
	blockNode, blockNodeDiags := body.Content(serviceRuleBlockSchema)
	if blockNodeDiags.HasErrors() {
		log.Fatalf("block content error: %v", blockNodeDiags)
	}
	name := ""
	policy := ""
	if attr, exists := blockNode.Attributes["name"]; exists {
		decodeDiags := gohcl.DecodeExpression(attr.Expr, nil, &name)
		if decodeDiags.HasErrors() {
			log.Fatalf("decode name attr error: %v", decodeDiags)
		}
	}
	if attr, exists := blockNode.Attributes["policy"]; exists {
		decodeDiags := gohcl.DecodeExpression(attr.Expr, nil, &policy)
		if decodeDiags.HasErrors() {
			log.Fatalf("decode policy attr error: %v", decodeDiags)
		}
	}
	aclPolicy.Services = append(aclPolicy.Services, &ServiceRule{Policy: policy, Name: name})
}

func parseServicePrefixBlock(body hcl.Body, aclPolicy *ACLPolicy) {
	blockNode, blockNodeDiags := body.Content(servicePrefixBlockSchema)
	if blockNodeDiags.HasErrors() {
		log.Fatalf("block content error: %v", blockNodeDiags)
	}
	name := ""
	policy := ""
	if attr, exists := blockNode.Attributes["name"]; exists {
		decodeDiags := gohcl.DecodeExpression(attr.Expr, nil, &name)
		if decodeDiags.HasErrors() {
			log.Fatalf("decode name attr error: %v", decodeDiags)
		}
	}
	if attr, exists := blockNode.Attributes["policy"]; exists {
		decodeDiags := gohcl.DecodeExpression(attr.Expr, nil, &policy)
		if decodeDiags.HasErrors() {
			log.Fatalf("decode policy attr error: %v", decodeDiags)
		}
	}
	aclPolicy.ServicePrefixes = append(aclPolicy.ServicePrefixes, &ServiceRule{Policy: policy, Name: name})
}
func main() {
	filename := "acl_policy2.hcl"
	config, errs := Parse(filename)
	if len(errs) > 0 {
		fmt.Println("error parsing file: ", errs)
		return
	}
	fmt.Println("PARSED CONFIG")
	if len(config.Nodes) > 0 {
		fmt.Println("** node policies ** ")
		for _, node := range config.Nodes {
			fmt.Printf("%v\n", node)
		}
	}
	if len(config.NodePrefixes) > 0 {
		fmt.Println("** node prefix policies **")
		for _, node := range config.NodePrefixes {
			fmt.Printf("%v\n", node)
		}
	}
	if len(config.Services) > 0 {
		fmt.Println("** service policies **")
		for _, node := range config.Services {
			fmt.Printf("%v\n", node)
		}
	}
	if len(config.ServicePrefixes) > 0 {
		fmt.Println("** service prefix policies **")
		for _, node := range config.ServicePrefixes {
			fmt.Printf("%v\n", node)
		}
	}
}

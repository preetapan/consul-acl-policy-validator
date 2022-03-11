package main

import (
	"errors"
	//"errors"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParseFile(t *testing.T) {

	var tests = []struct {
		fileName string
		errs     []error
		expected *ACLPolicy
	}{
		{"acl_policy1.hcl", nil,
			&ACLPolicy{ACL: "read",
				Nodes:           []*NodeRule{&NodeRule{Name: "test", Policy: "write"}},
				NodePrefixes:    []*NodeRule{&NodeRule{Name: "windows", Policy: "write"}},
				Services:        []*ServiceRule{&ServiceRule{Name: "Database", Policy: "write"}},
				ServicePrefixes: []*ServiceRule{&ServiceRule{Name: "APIService", Policy: "read"}},
			}},
		{"acl_policy2.hcl", []error{
			errors.New("acl_policy2.hcl:3,3-7: Unsupported block type; Blocks of type \"yolo\" are not expected here."),
			errors.New("acl_policy2.hcl:7,3-15: Unsupported block type; Blocks of type \"node_preefix\" are not expected here. Did you mean \"node_prefix\"?"),
		},
			&ACLPolicy{ACL: "read",
				Nodes: []*NodeRule{&NodeRule{Name: "test", Policy: "write"}},
			}},
	}
	for _, tc := range tests {
		t.Run(tc.fileName, func(t *testing.T) {
			require := require.New(t)
			config, errs := Parse(tc.fileName)
			if tc.errs != nil {
				for i, er := range errs {
					require.Equal(er.Error(), tc.errs[i].Error())
				}
			} else {
				require.Equal(tc.expected, config)
			}
		})
	}
}

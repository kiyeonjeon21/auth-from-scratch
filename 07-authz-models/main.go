// Command authz-models runs one scenario through three authorization models.
//
// Everything before this chapter answered "who is this". None of it answers
// "may they do this". The two are different questions, and the second one has
// its own family of designs.
//
// The point is not that one model wins. It is that the same requirement costs
// a different amount in each, and that real systems end up layering them.
//
// Read 07-authz-models/README.md before running.
package main

import (
	"fmt"
	"os"
	"strings"
)

// ------------------------------------------------------------------ 시나리오
//
// A document tool. Deliberately small, but it contains the one requirement
// that breaks RBAC: "the owner of a document may edit it", which is a fact
// about a *pair*, not about a person.

type user struct {
	name  string
	roles []string
	dept  string
}

type doc struct {
	id      string
	owner   string
	dept    string
	shared  []string // explicitly shared with
	classif string   // "normal" | "confidential"
}

type request struct {
	user   user
	action string // "read" | "edit"
	doc    doc
	// context, used only by ABAC
	fromOffice bool
}

var (
	alice = user{name: "alice", roles: []string{"editor"}, dept: "hr"}
	bob   = user{name: "bob", roles: []string{"viewer"}, dept: "hr"}
	carol = user{name: "carol", roles: []string{"admin"}, dept: "legal"}

	handbook = doc{id: "handbook", owner: "alice", dept: "hr", classif: "normal"}
	salaries = doc{id: "salaries", owner: "carol", dept: "hr",
		shared: []string{"alice"}, classif: "confidential"}
)

// ------------------------------------------------------------------ RBAC
//
// Permissions attach to roles; users get roles. Decisions need only the
// user's role list, which is why the role fits in a token claim.
//
// The limit is visible in the signature: the document is not an input to the
// grant table at all. "May edit documents" is as specific as it gets.

var rolePerms = map[string][]string{
	"viewer": {"read"},
	"editor": {"read", "edit"},
	"admin":  {"read", "edit", "delete"},
}

func rbac(r request) (bool, string) {
	for _, role := range r.user.roles {
		for _, p := range rolePerms[role] {
			if p == r.action {
				return true, fmt.Sprintf("역할 %q 에 %q 권한이 있다", role, r.action)
			}
		}
	}
	return false, fmt.Sprintf("역할 %v 중 %q 를 가진 게 없다", r.user.roles, r.action)
}

// ------------------------------------------------------------------ ABAC
//
// Decisions are computed from attributes of the subject, resource, action and
// environment at request time. Nothing is precomputed, so context like "is
// this person in the office" can matter.
//
// The cost is that the policy is code, and the inputs must all be available at
// the moment of the decision.

func abac(r request) (bool, string) {
	if r.doc.classif == "confidential" && !r.fromOffice {
		return false, "기밀 문서는 사무실 밖에서 못 본다 (환경 속성)"
	}
	if r.action == "read" {
		if r.user.dept == r.doc.dept {
			return true, fmt.Sprintf("같은 부서 (%s)", r.user.dept)
		}
		if has(r.user.roles, "admin") {
			return true, "admin은 부서 무관"
		}
		return false, fmt.Sprintf("부서가 다르다 (%s vs %s)", r.user.dept, r.doc.dept)
	}
	if r.action == "edit" {
		if r.doc.owner == r.user.name {
			return true, "문서 소유자다"
		}
		return false, "소유자가 아니다"
	}
	return false, "정책에 없는 동작"
}

// ------------------------------------------------------------------ ReBAC
//
// Decisions follow relationships between subject and object. The unit of
// storage is a tuple - (subject, relation, object) - and a check is a graph
// question, which is why this scales to "who can see this doc" style queries
// that the other two answer badly.

type tuple struct{ subject, relation, object string }

var tuples = []tuple{
	{"alice", "owner", "handbook"},
	{"carol", "owner", "salaries"},
	{"alice", "viewer", "salaries"}, // explicitly shared
	{"bob", "viewer", "handbook"},
}

// relationGrants says which relation implies which action.
var relationGrants = map[string][]string{
	"owner":  {"read", "edit"},
	"viewer": {"read"},
}

func rebac(r request) (bool, string) {
	for _, t := range tuples {
		if t.subject != r.user.name || t.object != r.doc.id {
			continue
		}
		for _, a := range relationGrants[t.relation] {
			if a == r.action {
				return true, fmt.Sprintf("%s 는 %s 의 %s 다", t.subject, t.object, t.relation)
			}
		}
	}
	return false, fmt.Sprintf("%s 와 %s 사이에 %q 를 허용하는 관계가 없다",
		r.user.name, r.doc.id, r.action)
}

// ------------------------------------------------------------------ 실행

func main() {
	cases := []struct {
		desc string
		req  request
		want bool
		why  string
	}{
		{"alice가 자기 문서를 수정", request{alice, "edit", handbook, true}, true,
			"소유자다"},
		{"alice가 남의 문서를 수정", request{alice, "edit", salaries, true}, false,
			"editor 역할은 있지만 소유자가 아니다 — 여기서 RBAC가 갈린다"},
		{"bob이 문서를 읽기", request{bob, "read", handbook, true}, true,
			"viewer 역할이자 공유받은 사람"},
		{"bob이 문서를 수정", request{bob, "edit", handbook, true}, false,
			"viewer는 수정 못 한다"},
		{"alice가 기밀문서를 사무실 밖에서 읽기", request{alice, "read", salaries, false}, false,
			"환경 속성 — RBAC/ReBAC는 이걸 볼 수 없다"},
	}

	models := []struct {
		name string
		fn   func(request) (bool, string)
	}{
		{"RBAC", rbac}, {"ABAC", abac}, {"ReBAC", rebac},
	}

	fmt.Println("== 같은 시나리오, 세 가지 인가 모델 ==")
	fmt.Println("   기대값은 '사람이 생각하는 옳은 답'이다. 모델이 그걸 표현할 수 있는지를 본다.")
	fmt.Println()

	mismatch := map[string][]string{}
	for _, c := range cases {
		fmt.Printf("   %s\n", c.desc)
		fmt.Printf("   기대: %s   (%s)\n", allow(c.want), c.why)
		for _, m := range models {
			got, reason := m.fn(c.req)
			mark := "  "
			if got != c.want {
				mark = "!!"
				mismatch[m.name] = append(mismatch[m.name], c.desc)
			}
			fmt.Printf("     %s %-6s %-6s %s\n", mark, m.name, allow(got), reason)
		}
		fmt.Println()
	}

	fmt.Println("== 모델별로 표현하지 못한 것 ==")
	for _, m := range models {
		bad := mismatch[m.name]
		if len(bad) == 0 {
			fmt.Printf("   %-6s 전부 표현함\n", m.name)
			continue
		}
		fmt.Printf("   %-6s %d건 못 맞춤\n", m.name, len(bad))
		for _, b := range bad {
			fmt.Printf("          - %s\n", b)
		}
	}

	fmt.Println()
	fmt.Println("== 그래서 =========================================")
	fmt.Println("   RBAC  : 자원을 입력으로 받지 않는다. '소유자만 수정'을 표현할 수 없다.")
	fmt.Println("           대신 결정에 필요한 게 역할 목록뿐이라 토큰 클레임에 들어간다.")
	fmt.Println("   ABAC  : 환경(사무실 여부)까지 본다. 유일하게 전부 표현했다.")
	fmt.Println("           대신 정책이 코드가 되고, 판단 시점에 모든 입력이 있어야 한다.")
	fmt.Println("   ReBAC : 관계를 저장하니 소유·공유가 자연스럽다.")
	fmt.Println("           대신 환경 속성은 관계가 아니라서 못 본다.")
	fmt.Println()
	fmt.Println("   실무는 하나를 고르지 않는다. 거친 정책은 RBAC, 자원 단위는 ReBAC,")
	fmt.Println("   문맥 규칙은 ABAC로 층을 쌓는다. 위 결과가 그 이유다.")

	if len(mismatch["ABAC"]) > 0 {
		os.Exit(1) // ABAC should express all of these; if not, the demo is wrong
	}
}

func allow(b bool) string {
	if b {
		return "허용"
	}
	return "거부"
}

func has(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

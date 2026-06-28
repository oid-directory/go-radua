package radua

import (
	"testing"
)

func TestStrInSlice(_ *testing.T) {
	_ = strInSlice(`test`, []string{"test", "testy", "testing"}, true)
	_ = strInSlice(`test`, []string{"Test", "tEsty", "testING"}, false)
	_ = strInSlice([]string{"test"}, []string{"test", "testy", "testing"}, false)
}

func TestSplitTags(_ *testing.T) {
	_ = splitTags(`tag1|c-tag1`)
}

func TestAssertTTL(_ *testing.T) {
	_ = assertTTL(`5`)
	_ = assertTTL(5)
}

func TestSelectTTL(_ *testing.T) {
	_ = selectTTL(`10`, ``, `6`)
	_ = selectTTL(`5`, `0`, ``)
	_ = selectTTL(``, `13`, `86400`)
	_ = selectTTL(``, `1`, ``)
}

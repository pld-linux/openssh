#!/bin/sh

# https://lists.mindrot.org/pipermail/openssh-unix-dev/2022-March/040086.html

set -e
url=https://github.com/openssh/openssh-portable.git
package=openssh
tag=V_9_0_P1
branch=V_9_0
out=$package-git.patch
repo=$package.git

# use filterdiff, etc to exclude bad chunks from diff
filter() {
	cat
}

if [ ! -d $repo ]; then
	git clone --bare $url -b $branch $repo
fi

cd $repo
	git fetch origin +$branch:$branch +refs/tags/$tag:refs/tags/$tag
	git log -p --reverse $tag..$branch ":(exclude)doc/doc-*" ":(exclude)test" ":(exclude).*" | filter > ../$out.tmp
cd ..

if cmp -s $out{,.tmp}; then
	echo >&2 "No new diffs..."
	rm -f $out.tmp
	exit 0
fi
mv -f $out{.tmp,}

../md5 $package.spec
../dropin $out

# Copyright 1999-2017 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2

EAPI=6

inherit cmake-utils

DESCRIPTION="Lookup public keys from a fixed directory"
HOMEPAGE="https://github.com/stschulte/lookup-ssh-pubkey"
SRC_URI="https://github.com/stschulte/lookup-ssh-pubkey/archive/v${PV}.tar.gz -> ${P}.tar.gz"

LICENSE="MIT"
SLOT="0"
KEYWORDS="~amd64 ~x86"

src_configure() {
	local mycmakeargs=( -DCMAKE_INSTALL_SYSCONFDIR:PATH=/etc )

	cmake-utils_src_configure
}

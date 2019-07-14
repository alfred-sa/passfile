# Maintainer: Alfred Sawaya <alfred@huji.fr>
# Contributor: Steve Fouchet <wakserz@gmail.com>
pkgname=passfile-git
pkgver=1.7
pkgrel=1
pkgdesc="world first ultimate secure password manager"
arch=('any')
url="https://github.com/whuji/${pkgname%-git}.git"
license=('GPL')
depends=('python>=3.6.0'
         'python-pycryptodomex>=3.6.1'
         'python-yaml>=3.13'
         'python-keyring>=17.1.1'
         'python-chardet>=3.0.4')
checkdepends=()
optdepends=('xdotool')
provides=("${pkgname%-git}")
options=()
install=
changelog=
source=("${pkgname%-git}::git+https://github.com/whuji/${pkgname/-/.}")
noextract=()
md5sums=('SKIP')
validpgpkeys=()

prepare() {
    pip3 install --user python-libxdo
}

package() {
    cd ${srcdir}/${pkgname%-git}
    install -Dm 755 ${pkgname%-git}.py ${pkgdir}/usr/bin/${pkgname%-git}
    cd ../../
    rm -rf ${pkgname%-git}
}

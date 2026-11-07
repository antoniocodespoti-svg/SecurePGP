package android.net

class DummyUri : Uri() {
    override fun isHierarchical(): Boolean = true
    override fun isOpaque(): Boolean = false
    override fun isRelative(): Boolean = false
    override fun getScheme(): String = "content"
    override fun getSchemeSpecificPart(): String = "test"
    override fun getEncodedSchemeSpecificPart(): String = "test"
    override fun getAuthority(): String = "test"
    override fun getEncodedAuthority(): String = "test"
    override fun getUserInfo(): String? = null
    override fun getEncodedUserInfo(): String? = null
    override fun getHost(): String = "test"
    override fun getPort(): Int = -1
    override fun getPath(): String = "/test"
    override fun getEncodedPath(): String = "/test"
    override fun getQuery(): String? = null
    override fun getEncodedQuery(): String? = null
    override fun getFragment(): String? = null
    override fun getEncodedFragment(): String? = null
    override fun getPathSegments(): List<String> = emptyList()
    override fun getLastPathSegment(): String? = null
    override fun buildUpon(): Builder? = null
    override fun writeToParcel(dest: android.os.Parcel, flags: Int) {}
    override fun describeContents(): Int = 0
    override fun compareTo(other: Uri?): Int = 0
    override fun toString(): String = "content://test"
}

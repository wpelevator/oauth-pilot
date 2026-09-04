<?php

namespace WPElevator\OAuth_Pilot;

class Asset_Meta {
	private string $path;

	private array $meta;

	public function __construct( $file_path ) {
		$this->path = rtrim( $file_path, '\\/' );
	}

	public function exists(): bool {
		return is_readable( $this->path );
	}

	public function get_path(): string {
		return $this->path;
	}

	public function get_url(): string {
		return plugins_url( basename( $this->path ), $this->path );
	}

	private function get_meta( $field = null ) {
		if ( ! isset( $this->meta ) ) {
			$this->meta = [
				'dependencies' => [],
				'version' => null,
			];

			$meta_path = sprintf(
				'%s/%s.asset.php',
				dirname( $this->path ),
				pathinfo( $this->path, PATHINFO_FILENAME )
			);

			if ( is_readable( $meta_path ) ) {
				$meta = include $meta_path;

				if ( isset( $meta['dependencies'] ) ) { // Merge only if recognized meta.
					$this->meta = array_merge( $this->meta, $meta );
				}
			}
		}

		if ( isset( $field ) ) {
			return $this->meta[ $field ] ?? null;
		}

		return $this->meta;
	}

	public function get_dependencies(): array {
		return $this->get_meta( 'dependencies' ) ?? [];
	}

	/**
	 * Hand written assets have no build meta beside them, so the file itself
	 * has to carry the cache busting version.
	 */
	public function get_version(): ?string {
		$version = $this->get_meta( 'version' );

		if ( isset( $version ) ) {
			return $version;
		}

		$modified = $this->exists() ? filemtime( $this->path ) : false;

		return ( false !== $modified ) ? (string) $modified : null;
	}
}

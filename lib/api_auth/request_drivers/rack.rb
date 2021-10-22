module ApiAuth
  module RequestDrivers # :nodoc:
    class RackRequest # :nodoc:
      include ApiAuth::Helpers

      def initialize(request)
        @request = request
        fetch_headers
        true
      end

      def set_auth_header(header)
        @request.env['Authorization'] = header
        fetch_headers
        @request
      end

      def request_body
        @request_body ||= if @request.body
                            body = @request.body.read
                            @request.body.rewind
                            body
                          else
                            ''
                          end
      end

      def calculated_hash
        sha256_base64digest(request_body)
      end

      def calculated_md5
        md5_base64digest(request_body)
      end

      def populate_content_hash
        return unless %w[POST PUT].include?(@request.request_method)

        @request.env['X-Authorization-Content-SHA256'] = calculated_hash
        fetch_headers
      end

      def content_hash_mismatch?
        return false unless %w[POST PUT].include?(@request.request_method)

        !content_hash_matches?
      end

      def content_hash_matches?
        request_hash = content_hash
        if @legacy_header
          calculated_md5 == request_hash
        else
          calculated_hash == request_hash
        end
      end

      def fetch_headers
        @headers = capitalize_keys @request.env
      end

      def http_method
        @request.request_method.upcase
      end

      def content_type
        find_header(%w[CONTENT-TYPE CONTENT_TYPE HTTP_CONTENT_TYPE])
      end

      def content_hash
        sha_hash = find_header(%w[X-AUTHORIZATION-CONTENT-SHA256 X_AUTHORIZATION_CONTENT_SHA256 HTTP_X_AUTHORIZATION_CONTENT_SHA256])
        if sha_hash
          @legacy_header = false
          sha_hash
        else
          @legacy_header = true
          find_header(%w[CONTENT-MD5 CONTENT_MD5 HTTP_CONTENT_MD5])
        end
      end

      def original_uri
        find_header(%w[X-ORIGINAL-URI X_ORIGINAL_URI HTTP_X_ORIGINAL_URI])
      end

      def request_uri
        @request.fullpath
      end

      def set_date
        @request.env['DATE'] = Time.now.utc.httpdate
        fetch_headers
      end

      def timestamp
        find_header(%w[DATE HTTP_DATE])
      end

      def authorization_header
        find_header %w[Authorization AUTHORIZATION HTTP_AUTHORIZATION]
      end

      private

      def find_header(keys)
        keys.map { |key| @headers[key] }.compact.first
      end
    end
  end
end

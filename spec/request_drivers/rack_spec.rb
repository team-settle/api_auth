require 'spec_helper'

describe ApiAuth::RequestDrivers::RackRequest do
  let(:timestamp) { Time.now.utc.httpdate }

  let(:request_path) { '/resource.xml?foo=bar&bar=foo' }

  let(:request_headers) do
    {
      'Authorization' => 'APIAuth 1044:12345',
      'X-Authorization-Content-SHA256' => '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=',
      'Content-Type' => 'text/plain',
      'Date' => timestamp
    }
  end

  let(:request) do
    Rack::Request.new(
      Rack::MockRequest.env_for(
        request_path,
        method: :put,
        input: "hello\nworld"
      ).merge!(request_headers)
    )
  end

  subject(:driven_request) { ApiAuth::RequestDrivers::RackRequest.new(request) }

  describe 'getting headers correctly' do
    it 'gets the content_type' do
      expect(driven_request.content_type).to eq('text/plain')
    end

    it 'gets the content_hash' do
      expect(driven_request.content_hash).to eq('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=')
    end

    it 'gets the request_uri' do
      expect(driven_request.request_uri).to eq('/resource.xml?foo=bar&bar=foo')
    end

    it 'gets the timestamp' do
      expect(driven_request.timestamp).to eq(timestamp)
    end

    it 'gets the authorization_header' do
      expect(driven_request.authorization_header).to eq('APIAuth 1044:12345')
    end

    describe '#calculated_hash' do
      it 'calculates hash from the body' do
        expect(driven_request.calculated_hash).to eq('JsYKYdAdtYNspw/v1EpqAWYgQTyO9fJZpsVhLU9507g=')
      end

      it 'treats no body as empty string' do
        request = Rack::Request.new(
          Rack::MockRequest.env_for(
            request_path,
            method: :put
          ).merge!(request_headers)
        )
        driven_request = ApiAuth::RequestDrivers::RackRequest.new(request)
        expect(driven_request.calculated_hash).to eq('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=')
      end
    end

    describe 'http_method' do
      context 'when put request' do
        let(:request) do
          Rack::Request.new(
            Rack::MockRequest.env_for(
              request_path,
              method: :put
            ).merge!(request_headers)
          )
        end

        it 'returns upcased put' do
          expect(driven_request.http_method).to eq('PUT')
        end
      end

      context 'when get request' do
        let(:request) do
          Rack::Request.new(
            Rack::MockRequest.env_for(
              request_path,
              method: :get
            ).merge!(request_headers)
          )
        end

        it 'returns upcased get' do
          expect(driven_request.http_method).to eq('GET')
        end
      end
    end
  end

  describe 'setting headers correctly' do
    let(:request_headers) do
      {
        'content-type' => 'text/plain'
      }
    end

    describe '#populate_content_hash' do
      context 'when getting' do
        let(:request) do
          Rack::Request.new(
            Rack::MockRequest.env_for(
              request_path,
              method: :get
            ).merge!(request_headers)
          )
        end

        it "doesn't populate content hash" do
          driven_request.populate_content_hash
          expect(request.env['X-Authorization-Content-SHA256']).to be_nil
        end
      end

      context 'when posting' do
        let(:request) do
          Rack::Request.new(
            Rack::MockRequest.env_for(
              request_path,
              method: :post,
              input: "hello\nworld"
            ).merge!(request_headers)
          )
        end

        it 'populates content hash' do
          driven_request.populate_content_hash
          expect(request.env['X-Authorization-Content-SHA256']).to eq('JsYKYdAdtYNspw/v1EpqAWYgQTyO9fJZpsVhLU9507g=')
        end

        it 'refreshes the cached headers' do
          driven_request.populate_content_hash
          expect(driven_request.content_hash).to eq('JsYKYdAdtYNspw/v1EpqAWYgQTyO9fJZpsVhLU9507g=')
        end
      end

      context 'when putting' do
        let(:request) do
          Rack::Request.new(
            Rack::MockRequest.env_for(
              request_path,
              method: :put,
              input: "hello\nworld"
            ).merge!(request_headers)
          )
        end

        it 'populates content hash' do
          driven_request.populate_content_hash
          expect(request.env['X-Authorization-Content-SHA256']).to eq('JsYKYdAdtYNspw/v1EpqAWYgQTyO9fJZpsVhLU9507g=')
        end

        it 'refreshes the cached headers' do
          driven_request.populate_content_hash
          expect(driven_request.content_hash).to eq('JsYKYdAdtYNspw/v1EpqAWYgQTyO9fJZpsVhLU9507g=')
        end
      end

      context 'when deleting' do
        let(:request) do
          Rack::Request.new(
            Rack::MockRequest.env_for(
              request_path,
              method: :delete
            ).merge!(request_headers)
          )
        end

        it "doesn't populate content hash" do
          driven_request.populate_content_hash
          expect(request.env['X-Authorization-Content-SHA256']).to be_nil
        end
      end
    end

    describe '#set_date' do
      before do
        allow(Time).to receive_message_chain(:now, :utc, :httpdate).and_return(timestamp)
      end

      it 'sets the date header of the request' do
        driven_request.set_date
        expect(request.env['DATE']).to eq(timestamp)
      end

      it 'refreshes the cached headers' do
        driven_request.set_date
        expect(driven_request.timestamp).to eq(timestamp)
      end
    end

    describe '#set_auth_header' do
      it 'sets the auth header' do
        driven_request.set_auth_header('APIAuth 1044:54321')
        expect(request.env['Authorization']).to eq('APIAuth 1044:54321')
      end
    end
  end

  describe 'content_hash_mismatch?' do
    context 'when getting' do
      let(:request) do
        Rack::Request.new(
          Rack::MockRequest.env_for(
            request_path,
            method: :get
          ).merge!(request_headers)
        )
      end

      it 'is false' do
        expect(driven_request.content_hash_mismatch?).to be false
      end
    end

    context 'when posting' do
      let(:request) do
        Rack::Request.new(
          Rack::MockRequest.env_for(
            request_path,
            method: :post,
            input: "hello\nworld"
          ).merge!(request_headers)
        )
      end

      context 'when calculated matches sent as SHA256' do
        before do
          request.env['X-Authorization-Content-SHA256'] = 'JsYKYdAdtYNspw/v1EpqAWYgQTyO9fJZpsVhLU9507g='
        end

        it 'is false' do
          expect(driven_request.content_hash_mismatch?).to be false
        end
      end

      context 'when calculated matches sent as MD5' do
        before do
          request.env['X-Authorization-Content-SHA256'] = nil
          request.env['Content-MD5'] = 'kZXQvrKoieG+Be1rsZVINw=='
        end

        it 'is false' do
          expect(driven_request.content_hash_mismatch?).to be false
        end
      end

      context "when calculated doesn't match sent as SHA256" do
        before do
          request.env['X-Authorization-Content-SHA256'] = 'kZXQvrKoieG+Be1rsZVINw=='
        end

        it 'is true' do
          expect(driven_request.content_hash_mismatch?).to be true
        end
      end

      context "when calculated doesn't match sent as MD5" do
        before do
          request.env['X-Authorization-Content-SHA256'] = nil
          request.env['Content-MD5'] = 'JsYKYdAdtYNspw/v1EpqAWYgQTyO9fJZpsVhLU9507g='
        end

        it 'is true' do
          expect(driven_request.content_hash_mismatch?).to be true
        end
      end
    end

    context 'when putting' do
      let(:request) do
        Rack::Request.new(
          Rack::MockRequest.env_for(
            request_path,
            method: :put,
            input: "hello\nworld"
          ).merge!(request_headers)
        )
      end

      context 'when calculated matches sent' do
        before do
          request.env['X-Authorization-Content-SHA256'] = 'JsYKYdAdtYNspw/v1EpqAWYgQTyO9fJZpsVhLU9507g='
        end

        it 'is false' do
          expect(driven_request.content_hash_mismatch?).to be false
        end
      end

      context "when calculated doesn't match sent" do
        before do
          request.env['X-Authorization-Content-SHA256'] = '3'
        end

        it 'is true' do
          expect(driven_request.content_hash_mismatch?).to be true
        end
      end
    end

    context 'when deleting' do
      let(:request) do
        Rack::Request.new(
          Rack::MockRequest.env_for(
            request_path,
            method: :delete
          ).merge!(request_headers)
        )
      end

      it 'is false' do
        expect(driven_request.content_hash_mismatch?).to be false
      end
    end
  end

  describe 'fetch_headers' do
    it 'returns request headers' do
      expect(driven_request.fetch_headers).to include('CONTENT-TYPE' => 'text/plain')
    end
  end
end

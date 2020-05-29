package serverless_mfa_api_go

import (
	"bytes"
	"log"
	"testing"
)

func TestApiKey_IsCorrect(t *testing.T) {
	tests := []struct {
		name         string
		HashedSecret string
		Given        string
		want         bool
		wantErr      bool
	}{
		{
			name:         "valid secret",
			HashedSecret: "$2y$10$Y.FlUK8q//DfybgFzNG2lONaJwvEFxHnCRo/r60BZbITDT6rOUhGa",
			Given:        "abc123",
			want:         true,
			wantErr:      false,
		},
		{
			name:         "invalid secret",
			HashedSecret: "$2y$10$Y.FlUK8q//DfybgFzNG2lONaJwvEFxHnCRo/r60BZbITDT6rOUhGa",
			Given:        "123abc",
			want:         false,
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ApiKey{
				HashedSecret: tt.HashedSecret,
			}
			got, err := k.IsCorrect(tt.Given)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsCorrect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsCorrect() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestApiKey_Hash - test that hashed secret can ve verified
func TestApiKey_Hash(t *testing.T) {
	tests := []struct {
		name    string
		Secret  string
		wantErr bool
	}{
		{
			name:    "matching hash",
			Secret:  "abc123",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ApiKey{
				Secret: tt.Secret,
			}
			err := k.Hash()
			if (err != nil) != tt.wantErr {
				t.Errorf("Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(k.HashedSecret) == 0 {
				t.Error("hashed secret is empty after call to hash")
				return
			}
			valid, err := k.IsCorrect(tt.Secret)
			if err != nil {
				t.Errorf("hashed password not valid after hashing??? error: %s", err.Error())
				return
			}
			if !valid {
				t.Error("hmm, password is not valid but no errors???")
				return
			}
		})
	}
}

func TestApiKey_EncryptDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		secret    string
		plaintext []byte
		want      []byte
		wantErr   bool
	}{
		{
			name:      "test encrypt/decrypt",
			secret:    "ED86600E-3DBF-4C23-A0DA-9C55D448",
			plaintext: []byte("this is a plaintext string to be encrypted"),
			want:      []byte("this is a plaintext string to be encrypted"),
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k1 := &ApiKey{
				Secret: tt.secret,
			}
			k2 := &ApiKey{
				Secret: tt.secret,
			}

			encrypted, err := k1.Encrypt(tt.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			decrypted, err := k2.Decrypt(encrypted)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !bytes.Equal(tt.plaintext, tt.want) {
				t.Errorf("results from decypt do not match expected. Got: %s, wanted: %s", decrypted, tt.want)
				return
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	cipher := []byte("HCeTgDJcLEcvCk9XajQGtLg4ZsTdGqNR92Jl/yVZGlsDbtKAbKqNDHrA5gS7hGmfILO07lbtZBbXI0ouMjtUs8wh+xvvN1U82PBPQpqhAhK1r1ZoLDzHhQVMItf3z+NA/lIYps6lyBzUETiY53S1lQQGIze4dztdFUfBiR8t14EbAu4m3dzgaAqOMUTU7JXmnBJyF7b5yHJOIYfYn0v3DbrC9BM3D/nEzWUjs2u8rRGMnutr/PFM29RmPmP2qhr/VBYvRfwSV6hu0We40lWApmnpfBqNu969RoAL7SlPuv28tHOinD1eVLn1SP/ZqIpuQ4RI/JspYrT1Dhoz5+kKRHrQ/DzIpGZ6lNsI0Cui8BakQTMRKpfh6THAE/H5UVU4u0POLu2s0LT6q7vFQ7SVhleX8MwV4YhAkFIRTyHX908XdsjD0OcFfWRHVtdVqzkIF46FscCnRBL/ukkdcPf3+caUGlydMHUwo7H8Ysk6t5NUrmZ5Hg8g2XHbwyxBiHE+qCkyZ3hyQoPNgISDrAvu6VOYaBF/m6jXqP/7CkGmtaRQ/AXqe4Zo6sS4vdo2JEjMBclPU+j1/RGMbv+2BfD0+N+NiIu2nvB0N1v6vBEkgkeZSUBaGjBF3R+pxR4qnqHYDgaKehw7lX8LFB/2KuB4WxQfEcHxY6eOUdT7+FaNlGKX2ccJbG63uMxSkDMkeBN9DwCO8O32DKMJRo8NehrdZ1qybdim/HX8MYF+srPUik6s/Jv/C9J7isVkxdt92R62tukPPg8kdW7C0kzzk/Grs3auF4a1LzFApAcVE45tTOv96kyelPnRC3oFTHRUo98AWD0aP2oJ/Sb4eoe3YB5rab1dEoeP14+pQixkekamR44KyZEv7lBYSdKhHpRPqGe9EwDbuzN0XlVzTyQNQ8y8V2H5tPmYiYuRCwG5qVrKr4l+VWlDh1gOIUkXZmUp4zqg+2HtBRakbNtfrZ6ih+99p5upI8Wv7wa6z2rpJ92x2lnQurIP/YQUsFcxH13dlIwmc6EbCtAJlJIfjS0MA5VmM9yk5meEgM1500o28dTh7qzhLM9VYM9KKQBcD3tvVT+r2nEwouHONmWyZ2GJmVfJTzyWeVRSrLFKI57VqI6xP5FltKxZ8pTX9rtTOSdSeBY5GAAbnY0CBoUtf6As0guhUJlH3E0r9e+9FXId8Hhclwnm2uAKUygu2Fo0rC0Dz4TMgiWiD7iO5/jtBkn50/eFN7a0HEQg8Y9p0LLITCngIC4ugrGFemyvYs5DTqIAh4XT8vDjAagmTq7aiB9AMsSw7qK/IB4tfDDHLVJl86+TotCzZhZrFqSTVPyLw7YtVPRlkuSu+Fd7HGIxnKuZjDYODL3631YuMMInNinSLso8uSnXAZBsvW+/r06yWsSnl/y29xcfUxFLLkRZwoD2P1G6guODC8uCfsVepVGwEfTbAluKrenQrLZL0aiIzQkjZS2G8asR76Xj+m/IpNB8J8P3UAkMWRdSJllQCFcSHfEwEa2EtZqYjcnau8ekdl3WrRkXih9L0WV4A8qE+YHmAo/rRNm3gPAOInJK37KuVll6gf3aTy5ajqHpZOGlqXSMlknThtwau43SKFwxg7xMxgkWzluOaoAV3BamlCsBg204+JM5XW2lj/76tOUY7B7tpHcGgSUzDq+xIYlxyFietdosKSx/NiJyxEKa6/5mWfwmdc3H6DynOYiYsG5L21k1W50PTyYlsuY7ltDAokJnhzEtWyOO2zxDtqpvLASAYELmaYLZCLvvCLjzjDL2vKG55mdmSQFXwJHgEjRe1e8m+iB7XA5Bv2PYS0Q9YIBF3FjElYvjYTJxo6Q=")
	apiKey := ApiKey{
		Key:    "EC7C2E16-5028-432F-8AF2-A79A64CF3BC1",
		Secret: "1ED18444-7238-410B-A536-D6C15A3C",
	}

	plain, err := apiKey.Decrypt(cipher)
	if err != nil {
		t.Error(err)
		return
	}

	log.Printf("decrypted: %s", string(plain))
}

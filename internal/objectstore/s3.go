package objectstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type Store struct {
	client  *s3.Client
	presign *s3.PresignClient
	bucket  string
}
func (s *Store) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil { return nil, err }
	return out.Body, nil
}
type SignedRequest struct {
	URL       string              `json:"url"`
	Method    string              `json:"method"`
	Headers   map[string][]string `json:"headers"`
	ExpiresAt time.Time           `json:"expires_at"`
}

func New(endpoint, region, key, secret, bucket string) *Store {
	cfg := aws.Config{Region: region, Credentials: credentials.NewStaticCredentialsProvider(key, secret, "")}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) { o.BaseEndpoint = aws.String(endpoint); o.UsePathStyle = true })
	return &Store{client, s3.NewPresignClient(client), bucket}
}
func (s *Store) EnsureBucket(ctx context.Context) error {
	_, e := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &s.bucket})
	if e == nil {
		return nil
	}
	_, e = s.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &s.bucket})
	var owned *types.BucketAlreadyOwnedByYou
	if errors.As(e, &owned) {
		return nil
	}
	return e
}
func (s *Store) PresignUpload(ctx context.Context, key, contentType, sha256 string, size int64, ttl time.Duration) (SignedRequest, error) {
	expires := time.Now().UTC().Add(ttl)
	r, e := s.presign.PresignPutObject(ctx, &s3.PutObjectInput{Bucket: &s.bucket, Key: &key, ContentType: &contentType, ContentLength: &size, Metadata: map[string]string{"sha256": sha256}}, func(o *s3.PresignOptions) { o.Expires = ttl })
	if e != nil {
		return SignedRequest{}, e
	}
	return SignedRequest{r.URL, http.MethodPut, r.SignedHeader, expires}, nil
}
func (s *Store) PutObject(ctx context.Context, key, contentType, sha256 string, size int64, body io.Reader) error {
	_, e := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &s.bucket, Key: &key, Body: body, ContentType: &contentType, ContentLength: &size,
		Metadata: map[string]string{"sha256": sha256},
	})
	return e
}
func (s *Store) Verify(ctx context.Context, key, sha256 string, size int64) error {
	h, e := s.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &s.bucket, Key: &key})
	if e != nil {
		return e
	}
	if h.ContentLength == nil || *h.ContentLength != size || h.Metadata["sha256"] != sha256 {
		return fmt.Errorf("uploaded object integrity metadata mismatch")
	}
	return nil
}
func (s *Store) PresignDownload(ctx context.Context, key, filename string, ttl time.Duration) (SignedRequest, error) {
	expires := time.Now().UTC().Add(ttl)
	disposition := "attachment; filename=\"" + filename + "\""
	r, e := s.presign.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key, ResponseContentDisposition: &disposition}, func(o *s3.PresignOptions) { o.Expires = ttl })
	if e != nil {
		return SignedRequest{}, e
	}
	return SignedRequest{r.URL, http.MethodGet, r.SignedHeader, expires}, nil
}

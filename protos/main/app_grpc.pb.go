// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.25.0
// source: app.proto

package main

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	Accommodation_Register_FullMethodName = "/accommodation/Register"
	Accommodation_Login_FullMethodName    = "/accommodation/Login"
	Accommodation_GetAuth_FullMethodName  = "/accommodation/GetAuth"
)

// AccommodationClient is the client API for Accommodation service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AccommodationClient interface {
	Register(ctx context.Context, in *AuthRequest, opts ...grpc.CallOption) (*AuthResponse, error)
	Login(ctx context.Context, in *AuthRequest, opts ...grpc.CallOption) (*Empty, error)
	GetAuth(ctx context.Context, in *AuthGet, opts ...grpc.CallOption) (*AuthResponse, error)
}

type accommodationClient struct {
	cc grpc.ClientConnInterface
}

func NewAccommodationClient(cc grpc.ClientConnInterface) AccommodationClient {
	return &accommodationClient{cc}
}

func (c *accommodationClient) Register(ctx context.Context, in *AuthRequest, opts ...grpc.CallOption) (*AuthResponse, error) {
	out := new(AuthResponse)
	err := c.cc.Invoke(ctx, Accommodation_Register_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accommodationClient) Login(ctx context.Context, in *AuthRequest, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := c.cc.Invoke(ctx, Accommodation_Login_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accommodationClient) GetAuth(ctx context.Context, in *AuthGet, opts ...grpc.CallOption) (*AuthResponse, error) {
	out := new(AuthResponse)
	err := c.cc.Invoke(ctx, Accommodation_GetAuth_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AccommodationServer is the server API for Accommodation service.
// All implementations must embed UnimplementedAccommodationServer
// for forward compatibility
type AccommodationServer interface {
	Register(context.Context, *AuthRequest) (*AuthResponse, error)
	Login(context.Context, *AuthRequest) (*Empty, error)
	GetAuth(context.Context, *AuthGet) (*AuthResponse, error)
	mustEmbedUnimplementedAccommodationServer()
}

// UnimplementedAccommodationServer must be embedded to have forward compatible implementations.
type UnimplementedAccommodationServer struct {
}

func (UnimplementedAccommodationServer) Register(context.Context, *AuthRequest) (*AuthResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Register not implemented")
}
func (UnimplementedAccommodationServer) Login(context.Context, *AuthRequest) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Login not implemented")
}
func (UnimplementedAccommodationServer) GetAuth(context.Context, *AuthGet) (*AuthResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAuth not implemented")
}
func (UnimplementedAccommodationServer) mustEmbedUnimplementedAccommodationServer() {}

// UnsafeAccommodationServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AccommodationServer will
// result in compilation errors.
type UnsafeAccommodationServer interface {
	mustEmbedUnimplementedAccommodationServer()
}

func RegisterAccommodationServer(s grpc.ServiceRegistrar, srv AccommodationServer) {
	s.RegisterService(&Accommodation_ServiceDesc, srv)
}

func _Accommodation_Register_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccommodationServer).Register(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Accommodation_Register_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccommodationServer).Register(ctx, req.(*AuthRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Accommodation_Login_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccommodationServer).Login(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Accommodation_Login_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccommodationServer).Login(ctx, req.(*AuthRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Accommodation_GetAuth_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthGet)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccommodationServer).GetAuth(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Accommodation_GetAuth_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccommodationServer).GetAuth(ctx, req.(*AuthGet))
	}
	return interceptor(ctx, in, info, handler)
}

// Accommodation_ServiceDesc is the grpc.ServiceDesc for Accommodation service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Accommodation_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "accommodation",
	HandlerType: (*AccommodationServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Register",
			Handler:    _Accommodation_Register_Handler,
		},
		{
			MethodName: "Login",
			Handler:    _Accommodation_Login_Handler,
		},
		{
			MethodName: "GetAuth",
			Handler:    _Accommodation_GetAuth_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "app.proto",
}

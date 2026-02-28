const std = @import("std");
const common = @import("common.zig");

pub fn execute(
    allocator: std.mem.Allocator,
    query: []const u8,
    api_key: ?[]const u8,
    timeout_secs: u64,
) (common.ProviderSearchError || error{OutOfMemory})!common.ToolResult {
    const encoded_query = try common.urlEncodePath(allocator, query);
    defer allocator.free(encoded_query);

    const url_str = try std.fmt.allocPrint(allocator, "https://s.jina.ai/{s}", .{encoded_query});
    defer allocator.free(url_str);

    const timeout_str = try common.timeoutToString(allocator, timeout_secs);
    defer allocator.free(timeout_str);

    if (api_key) |key| {
        const auth_header = try std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{key});
        defer allocator.free(auth_header);
        const x_key_header = try std.fmt.allocPrint(allocator, "x-api-key: {s}", .{key});
        defer allocator.free(x_key_header);

        const headers = [_][]const u8{
            "Accept: text/plain",
            auth_header,
            x_key_header,
        };

        const body = common.curlGet(allocator, url_str, &headers, timeout_str) catch |err| {
            common.logRequestError("jina", query, err);
            return err;
        };
        defer allocator.free(body);

        return common.formatJinaPlainText(allocator, body, query);
    }

    const headers = [_][]const u8{"Accept: text/plain"};
    const body = common.curlGet(allocator, url_str, &headers, timeout_str) catch |err| {
        common.logRequestError("jina", query, err);
        return err;
    };
    defer allocator.free(body);

    return common.formatJinaPlainText(allocator, body, query);
}

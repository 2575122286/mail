export async function onRequest(context) {
    const { request, next } = context;
    const url = new URL(request.url);
    
    // 绕过验证的条件
    const bypassConditions = [
        url.pathname === '/verify.html',
        url.pathname.startsWith('/assets/'),
        request.cf.bot_management.verified_bot, // 允许搜索引擎bot
        request.headers.get('sec-fetch-dest') === 'script'
    ];
    
    if (bypassConditions.some(cond => cond)) {
        return next();
    }
    
    // 检查验证令牌
    const verifyToken = url.searchParams.get('verify_token');
    const cookieToken = request.headers
        .get('Cookie')
        ?.split('; ')
        .find(c => c.startsWith('cf_verification='))
        ?.split('=')[1];
    
    // 验证逻辑
    if (!verifyToken || !cookieToken || verifyToken !== cookieToken) {
        return Response.redirect(`${url.origin}/verify.html`, 302);
    }
    
    // 添加安全头
    const response = await next();
    response.headers.set('X-Content-Type-Options', 'nosniff');
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    return response;
}

# Tool Status and Installation API Endpoints
@app.get("/api/tools/status")
def get_tools_status():
    """Get current tool installation status"""
    try:
        from src.utils.tool_checker import get_tool_checker
        tool_checker = get_tool_checker()
        
        return jsonify({
            "status": "success",
            "tools": tool_checker.tools_status,
            "summary": {
                "total_tools": len(tool_checker.tools_status),
                "installed_tools": len([t for t in tool_checker.tools_status.values() if t["installed"]]),
                "missing_essential": tool_checker.get_missing_essential_tools(),
                "system": tool_checker.system
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


@app.post("/api/tools/install")
def install_tools():
    """Auto-install missing tools (Linux only)"""
    try:
        from src.utils.tool_checker import get_tool_checker
        tool_checker = get_tool_checker()
        
        data = request.get_json() or {}
        tools_to_install = data.get("tools", tool_checker.get_missing_essential_tools())
        
        if tool_checker.system != "linux":
            return jsonify({
                "status": "error",
                "error": "Auto-installation only supported on Linux systems",
                "install_script": tool_checker.generate_installation_script()
            })
        
        installation_results = tool_checker.auto_install_tools(tools_to_install)
        
        return jsonify({
            "status": "success",
            "installation_results": installation_results,
            "updated_status": tool_checker.tools_status
        })
        
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


@app.get("/api/tools/install-script")
def get_install_script():
    """Get installation script for manual installation"""
    try:
        from src.utils.tool_checker import get_tool_checker
        tool_checker = get_tool_checker()
        
        script = tool_checker.generate_installation_script()
        instructions = tool_checker.get_install_instructions()
        
        return jsonify({
            "status": "success",
            "script": script,
            "instructions": instructions,
            "system": tool_checker.system
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})


@app.get("/tools-status")
def tools_status_page():
    """Tools status management page"""
    return render_template("tools_status.html")
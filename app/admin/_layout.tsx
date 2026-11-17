import { Redirect, Stack } from "expo-router";
import React, { useEffect, useState } from "react";
import { ActivityIndicator, View } from "react-native";
import { useAuth } from "../../lib/AuthContext";
import { adminService } from "../../lib/adminService";

export default function AdminLayout(): React.JSX.Element {
  const { user, loading: authLoading } = useAuth();
  const [checking, setChecking] = useState(true);
  const [authorized, setAuthorized] = useState(false);

  useEffect(() => {
    let cancelled = false;

    const checkAccess = async (): Promise<void> => {
      if (authLoading) return;
      if (!user) {
        if (!cancelled) {
          setAuthorized(false);
          setChecking(false);
        }
        return;
      }

      setChecking(true);
      const isAdmin = await adminService.isAdmin();
      if (!cancelled) {
        setAuthorized(isAdmin);
        setChecking(false);
      }
    };

    void checkAccess();
    return () => {
      cancelled = true;
    };
  }, [authLoading, user?.id]);

  if (authLoading || checking) {
    return (
      <View style={{ flex: 1, alignItems: "center", justifyContent: "center", backgroundColor: "#fff" }}>
        <ActivityIndicator size="large" color="#1293DA" />
      </View>
    );
  }

  if (!user) return <Redirect href="/auth/login" />;
  if (!authorized) return <Redirect href="/(tabs)" />;

  return <Stack screenOptions={{ headerShown: false }} />;
}
